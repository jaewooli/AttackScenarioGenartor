"""범용 DSL 규칙 평가기 (WBS 3.1).

`src/scengen/rules/*.yaml`의 선언적 규칙을 그대로 실행해 공격자 상태 사실(Fact)과 유도 단계(DerivationStep)를
고정점까지 만든다. 얇은 엔진(`thin.py`)이 Python으로 직접 짠 R1~R11을 대체하는 것이 목적이며,
얇은 엔진은 사실 집합 회귀 기준선으로 남긴다.

평가 순서 (규칙 1건):
1. `requires`의 사실 패턴(단, `knows` 제외)을 현재 사실 집합과 맞춰 변수를 묶는다.
2. `when` 절을 계획기(planner)가 고른 순서로 평가한다. 변수가 모두 묶인 절(검사)을 먼저,
   그다음 관계·자산 생성 절, 마지막으로 도메인 열거가 필요한 절을 평가한다.
3. `knows` 전제를 확인한다 (`uninformed` 변형만. `informed`에서는 전제에서 빠진다).
4. 확률 = base 분포 기대값 × 일치한 modifiers × (capability_scale이면 역량 계수) × Π(사용한 IR 관계·속성 confidence).
   base 분포 표본화는 WBS 3.4(몬테카를로)에서 한다.

재현성: 사실·자산·관계를 항상 정해진 순서로 순회하므로 PYTHONHASHSEED와 무관하게 같은 결과가 나온다.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from ..ir.validate import profile_variants
from ..rules.loader import RULES_DIR, WHEN_CLAUSES, load_rules
from .graph import InfraGraph, is_group_ref, strip_group_prefix
from .model import CAPABILITY_FACTOR, PRIVILEGE_ORDER, DerivationStep, Fact, VariantResult, obj_confidence, priv_at_least, unwrap_attr

# 관계 속성이 생략됐을 때의 의미 (IR 스펙 기본값)
REL_ATTR_DEFAULTS: dict[str, Any] = {
    "effect": "allow",
    "action": "read",
    "encrypted": False,
    "privilege": "user",
    "frequency": "unknown",
}

# 조건부 권한(has_permission.condition)은 조건 충족 여부를 모르므로 확률을 낮춘다 (얇은 엔진과 같은 값)
CONDITION_FACTOR = 0.7

PROB_MAX = 0.99

FACT_PAT_RE = re.compile(r"^([a-z_]+)\(([^)]*)\)$")
VAR_RE = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_]*)")

# 계획기 우선순위: 변수를 직접 만들어 내는 절
GENERATOR_CLAUSES = {"relation", "asset_type", "asset_role", "in_group", "group_parent"}



class RuleEvalError(ValueError):
    """규칙을 실행할 수 없을 때 (규칙 검증기가 놓친 형식 오류)."""


@dataclass(frozen=True)
class Bind:
    """변수 바인딩 1건과 그 바인딩을 만들 때 쓴 IR 근거."""

    env: tuple[tuple[str, Any], ...] = ()
    conf: float = 1.0
    evidence: tuple[str, ...] = ()
    premises: tuple[Fact, ...] = ()
    perm_action: str | None = None

    def get(self, var: str) -> Any:
        for k, v in self.env:
            if k == var:
                return v
        return None

    def has(self, var: str) -> bool:
        return any(k == var for k, _ in self.env)

    def with_var(self, var: str, value: Any) -> Bind:
        return Bind(self.env + ((var, value),), self.conf, self.evidence, self.premises, self.perm_action)

    def scaled(self, factor: float, evidence: str | None = None) -> Bind:
        ev = self.evidence + ((evidence,) if evidence else ())
        return Bind(self.env, self.conf * factor, ev, self.premises, self.perm_action)

    def with_premise(self, fact: Fact) -> Bind:
        return Bind(self.env, self.conf, self.evidence, self.premises + (fact,), self.perm_action)

    def with_action(self, action: str) -> Bind:
        return Bind(self.env, self.conf, self.evidence, self.premises, action)


@dataclass(frozen=True)
class FactPattern:
    kind: str
    args: tuple[str, ...]

    @classmethod
    def parse(cls, expr: str) -> FactPattern:
        m = FACT_PAT_RE.match(expr.strip())
        if not m:
            raise RuleEvalError(f"잘못된 사실 패턴 '{expr}'")
        args = tuple(a.strip() for a in m.group(2).split(",") if a.strip())
        return cls(m.group(1), args)


@dataclass
class CompiledRule:
    id: str
    name: str
    category: str
    vars: dict[str, dict[str, Any]]
    when: list[dict[str, Any]]
    requires: list[Any]  # FactPattern 또는 ("any", [FactPattern...])
    adds: list[FactPattern]
    base_mean: float
    capability_scale: bool
    modifiers: list[tuple[dict[str, Any], float]] = field(default_factory=list)
    techniques: tuple[str, ...] = ()


def _compile_requires(items: list[Any]) -> list[Any]:
    out: list[Any] = []
    for item in items:
        if isinstance(item, dict) and "any" in item:
            out.append(("any", [FactPattern.parse(str(x)) for x in item["any"]]))
        elif isinstance(item, dict) and "all" in item:
            out.extend(_compile_requires(item["all"]))
        else:
            out.append(FactPattern.parse(str(item)))
    return out


def compile_rule(raw: dict[str, Any]) -> CompiledRule:
    prob = raw.get("probability") or {}
    base = prob.get("base") or {}
    a, b = float(base.get("alpha", 1.0)), float(base.get("beta", 1.0))
    mods = [(m["when"], float(m["factor"])) for m in prob.get("modifiers") or []]
    return CompiledRule(
        id=raw["id"],
        name=raw.get("name", raw["id"]),
        category=raw["category"],
        vars=raw.get("vars") or {},
        when=list(raw.get("when") or []),
        requires=_compile_requires(list(raw.get("requires") or [])),
        adds=[FactPattern.parse(str(x)) for x in raw.get("adds") or []],
        base_mean=a / (a + b),
        capability_scale=bool(prob.get("capability_scale")),
        modifiers=mods,
        techniques=tuple(raw.get("attack_techniques") or ()),
    )


def load_ruleset(rules_dir: str | Path = RULES_DIR, files: list[str] | None = None) -> list[CompiledRule]:
    """규칙 검증기를 통과한 규칙만 컴파일한다. files를 주면 해당 파일명(예: core.yaml)만 읽는다."""
    res = load_rules(rules_dir, files=files)
    if not res.ok:
        raise RuleEvalError("규칙 검증 실패: " + "; ".join(res.errors))
    return [compile_rule(r) for r in res.rules]


_CLAUSE_VARS_CACHE: dict[int, tuple[Any, frozenset[str]]] = {}


def _clause_vars(clause: Any) -> frozenset[str]:
    """절에 나오는 변수 이름. 규칙 객체는 실행 중 바뀌지 않으므로 객체 id로 캐시한다."""
    if isinstance(clause, str):
        return frozenset(VAR_RE.findall(clause))
    hit = _CLAUSE_VARS_CACHE.get(id(clause))
    if hit is not None and hit[0] is clause:
        return hit[1]
    result = frozenset(_collect_clause_vars(clause))
    _CLAUSE_VARS_CACHE[id(clause)] = (clause, result)  # 원본 참조를 함께 들고 있어 id 재사용을 막는다
    return result


def _collect_clause_vars(clause: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(clause, str):
        found.update(VAR_RE.findall(clause))
    elif isinstance(clause, list):
        for x in clause:
            found |= _collect_clause_vars(x)
    elif isinstance(clause, dict):
        for v in clause.values():
            found |= _collect_clause_vars(v)
    return found


def _is_var(x: Any) -> bool:
    return isinstance(x, str) and x.startswith("$")


class RuleEvaluator:
    """InfraGraph 위에서 CompiledRule 목록을 고정점까지 실행한다."""

    def __init__(self, graph: InfraGraph, rules: list[CompiledRule], capability: str, knowledge: str) -> None:
        self.g = graph
        self.rules = rules
        self.cap = CAPABILITY_FACTOR.get(capability, CAPABILITY_FACTOR["medium"])
        self.knowledge = knowledge
        self.facts: set[Fact] = set()
        self._sorted_facts: list[Fact] = []
        self._direct_groups: dict[str, set[str]] = {
            aid: set(a.get("groups") or []) for aid, a in graph.assets.items()
        }

    # ------------------------------------------------------------------ 실행
    def run(
        self, facts: set[Fact], derivs: dict[Fact, list[DerivationStep]]
    ) -> tuple[set[Fact], dict[Fact, list[DerivationStep]]]:
        self.facts = set(facts)
        derivs = defaultdict(list, {k: list(v) for k, v in derivs.items()})
        index: dict[tuple[str, Fact, tuple[Fact, ...]], int] = {}
        active = [r for r in self.rules if r.category != "discovery" or self.knowledge == "uninformed"]

        changed = True
        while changed:
            changed = False
            self._sorted_facts = sorted(self.facts, key=str)
            new_steps: list[DerivationStep] = []
            for rule in active:
                new_steps.extend(self._apply(rule))
            for step in new_steps:
                key = (step.rule_id, step.conclusion, step.premises)
                if key in index:
                    # 같은 전제에서 같은 결론: 확률이 더 높은 바인딩만 남긴다 (noisy-OR 이중 계산 방지)
                    steps = derivs[step.conclusion]
                    i = index[key]
                    if step.prob > steps[i].prob:
                        steps[i] = step
                    continue
                index[key] = len(derivs[step.conclusion])
                derivs[step.conclusion].append(step)
                if step.conclusion not in self.facts:
                    self.facts.add(step.conclusion)
                    changed = True
        return self.facts, dict(derivs)

    def _apply(self, rule: CompiledRule) -> Iterator[DerivationStep]:
        knows_pats: list[FactPattern] = []
        binds: list[Bind] = [Bind()]
        for req in rule.requires:
            if isinstance(req, FactPattern) and req.kind == "knows":
                knows_pats.append(req)
                continue
            alts = req[1] if isinstance(req, tuple) else [req]
            binds = [nb for b in binds for alt in alts for nb in self._match_fact(rule, alt, b)]
            if not binds:
                return

        for b in binds:
            for wb in self._solve(rule, list(rule.when), b):
                fb = wb
                if self.knowledge == "uninformed":
                    ok = True
                    for kp in knows_pats:
                        matched = list(self._match_fact(rule, kp, fb))
                        if not matched:
                            ok = False
                            break
                        fb = matched[0]
                    if not ok:
                        continue
                yield from self._emit(rule, fb)

    def _emit(self, rule: CompiledRule, b: Bind) -> Iterator[DerivationStep]:
        p = rule.base_mean
        for cond, factor in rule.modifiers:
            if next(iter(self._solve(rule, [cond], b)), None) is not None:
                p *= factor
        if rule.capability_scale:
            p *= self.cap
        p = round(min(PROB_MAX, p * b.conf), 4)
        if p <= 0.0:
            return
        sources = tuple(dict.fromkeys(b.evidence))
        for pat in rule.adds:
            concl = Fact(pat.kind, tuple(str(self._value(a, b)) for a in pat.args))
            if concl in b.premises:
                continue  # 자기 자신을 다시 유도하는 단계는 만들지 않는다
            note = ", ".join(f"{k}={v}" for k, v in b.env if not str(k).startswith("_"))
            yield DerivationStep(rule.id, concl, b.premises, p, note, sources)

    # ------------------------------------------------------------------ 사실 패턴
    def _match_fact(self, rule: CompiledRule, pat: FactPattern, b: Bind) -> Iterator[Bind]:
        if pat.kind == "foothold":
            # foothold(asset, level): level 이상인 거점 중 자산별 최고 수준 사실 하나와 맞춘다
            a_expr, min_lvl_expr = pat.args
            min_lvl = str(self._value(min_lvl_expr, b) or "none")
            best: dict[str, Fact] = {}
            for f in self._sorted_facts:
                if f.kind != "foothold" or not priv_at_least(f.args[1], min_lvl):
                    continue
                cur = best.get(f.args[0])
                if cur is None or PRIVILEGE_ORDER[f.args[1]] > PRIVILEGE_ORDER[cur.args[1]]:
                    best[f.args[0]] = f
            for asset_id, f in best.items():
                nb = self._unify(rule, a_expr, asset_id, b)
                if nb is not None:
                    yield nb.with_premise(f)
            return

        for f in self._sorted_facts:
            if f.kind != pat.kind or len(f.args) != len(pat.args):
                continue
            nb: Bind | None = b
            for expr, val in zip(pat.args, f.args):
                nb = self._unify(rule, expr, val, nb)
                if nb is None:
                    break
            if nb is not None:
                yield nb.with_premise(f)

    # ------------------------------------------------------------------ 변수
    def _unify(self, rule: CompiledRule, expr: str, value: Any, b: Bind | None) -> Bind | None:
        if b is None:
            return None
        if not _is_var(expr):
            return b if str(expr) == str(value) else None
        var = expr[1:]
        if b.has(var):
            return b if b.get(var) == value else None
        if not self._in_domain(rule, var, value):
            return None
        return b.with_var(var, value)

    def _in_domain(self, rule: CompiledRule, var: str, value: Any) -> bool:
        spec = rule.vars.get(var)
        if spec is None:
            raise RuleEvalError(f"{rule.id}: 선언되지 않은 변수 ${var}")
        vtype = spec.get("type", "asset")
        if vtype == "group":
            return value in self.g.groups
        if vtype == "level":
            return value in PRIVILEGE_ORDER
        if vtype in ("asset", "identity"):
            asset = self.g.assets.get(value) if isinstance(value, str) else None
            if asset is None:
                return False
            if vtype == "identity" and asset.get("type") != "identity":
                return False
            if "asset_type" in spec and asset.get("type") != spec["asset_type"]:
                return False
            if "kind" in spec and asset.get("kind") != spec["kind"]:
                return False
            return True
        return True  # value 등 자유 타입

    def _domain(self, rule: CompiledRule, var: str) -> list[Any]:
        spec = rule.vars.get(var) or {}
        vtype = spec.get("type", "asset")
        if vtype == "group":
            return list(self.g.groups)
        if vtype == "level":
            return list(PRIVILEGE_ORDER)
        if vtype in ("asset", "identity"):
            return [aid for aid in self.g.assets if self._in_domain(rule, var, aid)]
        raise RuleEvalError(f"{rule.id}: ${var}({vtype})는 열거할 수 없음. 먼저 묶는 절이 필요")

    def _value(self, expr: Any, b: Bind) -> Any:
        """$var 또는 $var.attr 값을 꺼낸다. 변수가 아니면 그대로 돌려준다."""
        if not _is_var(expr):
            return expr
        name, _, attr = expr[1:].partition(".")
        val = b.get(name)
        if not attr:
            return val
        asset = self.g.assets.get(val) or {}
        v, _, _ = unwrap_attr(asset.get(attr))
        return v

    def _ground(self, rule: CompiledRule, clause: Any, b: Bind) -> Iterator[Bind]:
        """절에 나오는 묶이지 않은 변수를 도메인에서 열거해 모두 묶는다."""
        unbound = sorted(v for v in _clause_vars(clause) if not b.has(v))
        if not unbound:
            yield b
            return
        var, rest = unbound[0], unbound[1:]
        for val in self._domain(rule, var):
            nb = b.with_var(var, val)
            if rest:
                yield from self._ground(rule, clause, nb)
            else:
                yield nb

    # ------------------------------------------------------------------ when 절
    def _priority(self, clause: dict[str, Any], b: Bind) -> int:
        if all(b.has(v) for v in _clause_vars(clause)):
            return 0
        if set(clause) & GENERATOR_CLAUSES:
            return 1
        return 2

    def _solve(self, rule: CompiledRule, clauses: list[dict[str, Any]], b: Bind) -> Iterator[Bind]:
        if not clauses:
            yield b
            return
        idx = min(range(len(clauses)), key=lambda i: (self._priority(clauses[i], b), i))
        clause, rest = clauses[idx], clauses[:idx] + clauses[idx + 1 :]
        for nb in self._eval_clause(rule, clause, b):
            yield from self._solve(rule, rest, nb)

    def _eval_clause(self, rule: CompiledRule, clause: dict[str, Any], b: Bind) -> Iterator[Bind]:
        if not isinstance(clause, dict):
            raise RuleEvalError(f"{rule.id}: when 절은 매핑이어야 함: {clause!r}")
        if len(clause) > 1:
            yield from self._solve(rule, [{k: v} for k, v in clause.items()], b)
            return
        (key, arg), = clause.items()
        handler = getattr(self, f"_c_{key}", None) if key in WHEN_CLAUSES else None
        if handler is None:
            raise RuleEvalError(f"{rule.id}: 알 수 없는 when 절 '{key}'")
        yield from handler(rule, arg, b)

    def _c_all(self, rule: CompiledRule, arg: list[dict[str, Any]], b: Bind) -> Iterator[Bind]:
        yield from self._solve(rule, list(arg), b)

    def _c_any(self, rule: CompiledRule, arg: list[dict[str, Any]], b: Bind) -> Iterator[Bind]:
        for branch in arg:
            yield from self._eval_clause(rule, branch, b)

    def _c_not(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        if next(iter(self._eval_clause(rule, arg, b)), None) is None:
            yield b

    def _c_neq(self, rule: CompiledRule, arg: list[Any], b: Bind) -> Iterator[Bind]:
        for gb in self._ground(rule, arg, b):
            if self._value(arg[0], gb) != self._value(arg[1], gb):
                yield gb

    def _c_eq(self, rule: CompiledRule, arg: list[Any], b: Bind) -> Iterator[Bind]:
        for gb in self._ground(rule, arg, b):
            if str(self._value(arg[0], gb)) == str(self._value(arg[1], gb)):
                yield gb

    def _c_asset_type(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        expr = arg["asset"]
        cands = [self._value(expr, b)] if not _is_var(expr) or b.has(expr[1:]) else self._domain(rule, expr[1:])
        for aid in cands:
            asset = self.g.assets.get(aid)
            if asset and asset.get("type") == arg["type"]:
                nb = self._unify(rule, expr, aid, b)
                if nb is not None:
                    yield nb

    def _c_asset_role(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        expr = arg["asset"]
        cands = [self._value(expr, b)] if not _is_var(expr) or b.has(expr[1:]) else list(self.g.assets)
        for aid in cands:
            asset = self.g.assets.get(aid)
            if not asset or asset.get("role") != arg["role"]:
                continue
            nb = self._unify(rule, expr, aid, b)
            if nb is None:
                continue
            if "in_group" not in arg:
                yield nb
                continue
            for gid in sorted(self._direct_groups.get(aid, ())):
                grp = self.g.groups.get(gid)
                if grp is None:
                    continue
                if "group_kind" in arg and grp.get("kind") != arg["group_kind"]:
                    continue
                gb = self._unify(rule, arg["in_group"], gid, nb)
                if gb is not None:
                    yield gb

    def _c_in_group(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        """자산이 그룹(조상 그룹 포함)에 속한다."""
        a_expr, g_expr = arg["asset"], arg["group"]
        if _is_var(g_expr) and not b.has(g_expr[1:]) and _is_var(a_expr) and b.has(a_expr[1:]):
            aid = self._value(a_expr, b)
            for gid in sorted(self.g.asset_groups(aid)):
                nb = self._unify(rule, g_expr, gid, b)
                if nb is not None:
                    yield nb
            return
        gids = [self._value(g_expr, b)] if not _is_var(g_expr) or b.has(g_expr[1:]) else self._domain(rule, g_expr[1:])
        for gid in gids:
            gb = self._unify(rule, g_expr, gid, b)
            if gb is None:
                continue
            for aid in self.g.assets_in_group(str(gid)):
                nb = self._unify(rule, a_expr, aid, gb)
                if nb is not None:
                    yield nb

    def _c_group_parent(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        for gid, grp in self.g.groups.items():
            parent = grp.get("parent")
            if not parent:
                continue
            nb = self._unify(rule, arg["child"], gid, b)
            nb = self._unify(rule, arg["parent"], parent, nb)
            if nb is not None:
                yield nb

    def _c_same_group(self, rule: CompiledRule, arg: list[Any], b: Bind) -> Iterator[Bind]:
        for gb in self._ground(rule, arg, b):
            a1, a2 = self._value(arg[0], gb), self._value(arg[1], gb)
            if self._direct_groups.get(a1, set()) & self._direct_groups.get(a2, set()):
                yield gb

    def _c_config(self, rule: CompiledRule, arg: list[Any], b: Bind) -> Iterator[Bind]:
        for gb in self._ground(rule, arg[0], b):
            aid = self._value(arg[0], gb)
            val, conf, _ = self.g.get_config(aid, arg[1])
            if val is not None and val == arg[2]:
                yield gb.scaled(conf if conf > 0 else 1.0, f"config:{aid}.{arg[1]}")

    def _c_config_set(self, rule: CompiledRule, arg: list[Any], b: Bind) -> Iterator[Bind]:
        for gb in self._ground(rule, arg[0], b):
            val, _, _ = self.g.get_config(self._value(arg[0], gb), arg[1])
            if val not in (None, "", [], {}):
                yield gb

    def _c_not_denied(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        for gb in self._ground(rule, arg, b):
            actor, target = self._value(arg["from"], gb), self._value(arg["to"], gb)
            denied = False
            for r in self.g.by_type.get("has_permission", []):
                if r.get("effect") != "deny" or r["from"] != actor:
                    continue
                if not (self.g.matches_target(target, r["to"]) or strip_group_prefix(r["to"]) == target):
                    continue
                act = r.get("action", REL_ATTR_DEFAULTS["action"])
                if gb.perm_action is None or act in (gb.perm_action, "admin"):
                    denied = True
                    break
            if not denied:
                yield gb

    def _c_reaches(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        for gb in self._ground(rule, arg, b):
            src, dst = self._value(arg["from"], gb), self._value(arg["to"], gb)
            port = self._value(arg.get("port"), gb) if "port" in arg else None
            proto = self._value(arg.get("protocol"), gb) if "protocol" in arg else None
            matches = self.g.can_reach(src, dst, port=port, protocol=proto)
            if matches:
                best = max(matches, key=lambda m: m.confidence)
                yield gb.scaled(best.confidence, f"reaches:{src}->{dst}")

    def _endpoint(self, rule: CompiledRule, expr: Any, ref: str, b: Bind, expand: bool) -> Iterator[Bind]:
        """관계 끝점 ref를 expr(변수/상수)와 맞춘다. 그룹 참조는 그룹 변수 또는 소속 자산으로 푼다."""
        if expr is None:
            yield b
            return
        if not _is_var(expr):
            if str(expr) == ref:
                yield b
            return
        var = expr[1:]
        vtype = (rule.vars.get(var) or {}).get("type", "asset")
        if is_group_ref(ref):
            gid = strip_group_prefix(ref)
            if vtype == "group":
                nb = self._unify(rule, expr, gid, b)
                if nb is not None:
                    yield nb
            elif expand:
                for aid in self.g.assets_in_group(gid):
                    nb = self._unify(rule, expr, aid, b)
                    if nb is not None:
                        yield nb
            return
        if vtype == "group":
            return
        nb = self._unify(rule, expr, ref, b)
        if nb is not None:
            yield nb

    def _endpoint_refs(self, rule: CompiledRule, expr: Any, b: Bind) -> list[str] | None:
        """끝점 expr이 이미 정해졌으면 관계에 적혔을 수 있는 참조 목록(자산 id + 소속 그룹 참조), 아니면 None."""
        if expr is None:
            return None
        if not _is_var(expr):
            return [str(expr)]
        var = expr[1:]
        if not b.has(var):
            return None
        val = b.get(var)
        if (rule.vars.get(var) or {}).get("type") == "group":
            return [f"group:{val}"]
        return [val] + [f"group:{gid}" for gid in sorted(self.g.asset_groups(val))]

    def _candidate_relations(self, rule: CompiledRule, rtype: str, arg: dict[str, Any], b: Bind) -> list[dict[str, Any]]:
        """끝점이 정해진 쪽의 인덱스로 후보 관계를 좁힌다. 순서는 IR에 적힌 순서를 유지한다."""
        for side, index in (("from", self.g.rel_index_from), ("to", self.g.rel_index_to)):
            refs = self._endpoint_refs(rule, arg.get(side), b)
            if refs is None:
                continue
            pos: set[int] = set()
            for ref in refs:
                pos.update(index.get((rtype, ref), ()))
            rels = self.g.by_type.get(rtype, [])
            return [rels[i] for i in sorted(pos)]
        return self.g.by_type.get(rtype, [])

    def _c_relation(self, rule: CompiledRule, arg: dict[str, Any], b: Bind) -> Iterator[Bind]:
        rtype = arg["type"]
        attrs = {k: v for k, v in arg.items() if k not in ("type", "from", "to", "action_in", "expand_groups")}
        for r in self._candidate_relations(rule, rtype, arg, b):
            if "action_in" in arg and r.get("action", REL_ATTR_DEFAULTS["action"]) not in arg["action_in"]:
                continue
            expand = arg.get("expand_groups", True) and r.get("inherit") is not False
            base = b.scaled(
                obj_confidence(r) * (CONDITION_FACTOR if r.get("condition") else 1.0),
                f"{rtype}:{r['from']}->{r['to']}",
            )
            if rtype == "has_permission":
                base = base.with_action(r.get("action", REL_ATTR_DEFAULTS["action"]))
            for fb in self._endpoint(rule, arg.get("from"), r["from"], base, expand):
                for tb in self._endpoint(rule, arg.get("to"), r["to"], fb, expand):
                    nb: Bind | None = tb
                    for k, expected in attrs.items():
                        raw = r.get(k)
                        val, conf, _ = unwrap_attr(raw, REL_ATTR_DEFAULTS.get(k))
                        if raw is None:
                            val, conf = REL_ATTR_DEFAULTS.get(k), 1.0
                        if val is None:
                            nb = None
                            break
                        if _is_var(expected):
                            nb = self._unify(rule, expected, val, nb)
                            if nb is not None and raw is not None and conf < 1.0:
                                nb = nb.scaled(conf)
                        elif val != expected:
                            nb = None
                        if nb is None:
                            break
                    if nb is not None:
                        yield nb


# ---------------------------------------------------------------------- 변형 실행
def run_variant_rules(
    graph: InfraGraph,
    profile: dict[str, Any],
    knowledge: str,
    egress: str,
    rules: list[CompiledRule] | None = None,
) -> VariantResult:
    """단일 (profile, knowledge, egress) 변형을 DSL 규칙으로 고정점까지 실행한다.

    초기 사실과 목표 판정은 얇은 엔진과 같은 함수를 쓴다 (목표 판정은 WBS 3.3 DAG로 대체 예정).
    """
    from .thin import _evaluate_goals, _initial_facts

    if rules is None:
        rules = load_ruleset()
    facts, derivs = _initial_facts(graph, profile, knowledge)
    ev = RuleEvaluator(graph, rules, profile.get("capability", "medium"), knowledge)
    facts, derivs = ev.run(facts, derivs)
    return VariantResult(
        profile_id=profile.get("id", "default"),
        knowledge=knowledge,
        egress=egress,
        facts=facts,
        derivations=derivs,
        goals=_evaluate_goals(graph, facts, derivs, egress),
    )


def analyze_doc_rules(doc: dict[str, Any], rules: list[CompiledRule] | None = None) -> list[VariantResult]:
    """IR 문서의 모든 공격자 프로필 × 분석 변형을 DSL 규칙으로 실행한다."""
    from .thin import resolve_profiles

    graph = InfraGraph(doc)
    if rules is None:
        rules = load_ruleset()
    return [
        run_variant_rules(graph, prof, var["knowledge"], var["egress"], rules)
        for prof in resolve_profiles(graph)
        for var in profile_variants(prof)
    ]
