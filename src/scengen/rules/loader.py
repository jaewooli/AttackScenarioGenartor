"""공격 단계 규칙 DSL 로더 및 정합성 검증기 (WBS 2.3 / 2.4)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..ir.validate import RELATION_RULES
from ..ir.vocab import CONFIG_KEYS

RULES_DIR = Path(__file__).resolve().parent  # 규칙 파일은 패키지 안(src/scengen/rules/*.yaml)에 둔다
CATEGORIES = {"transition", "privilege_escalation", "discovery"}
FACT_KINDS = {"foothold", "acts_as", "has_credential", "controls", "data_access", "knows"}
FACT_RE = re.compile(r"^([a-z_]+)\(([^)]+)\)$")
# 평가기(engine/rule_eval.py)가 실행할 수 있는 when 절. 여기 없는 절은 조용히 무시되지 않도록 오류로 처리한다.
WHEN_CLAUSES = {
    "relation", "reaches", "config", "config_set", "not_denied", "neq", "eq",
    "same_group", "asset_type", "asset_role", "in_group", "group_parent",
    "any", "all", "not",
}
VAR_TYPES = {"asset", "identity", "group", "level", "value"}
TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
VAR_RE = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_]*)")


@dataclass
class RuleValidationResult:
    rules: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    referenced_relations: set[str] = field(default_factory=set)
    referenced_configs: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return not self.errors


def _collect_vars(obj: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, str):
        found.update(VAR_RE.findall(obj))
    elif isinstance(obj, list):
        for item in obj:
            found.update(_collect_vars(item))
    elif isinstance(obj, dict):
        for val in obj.values():
            found.update(_collect_vars(val))
    return found


def _walk_when(clause: Any, errors: list[str], rels: set[str], cfgs: set[str], prefix: str) -> None:
    if isinstance(clause, list):
        for idx, item in enumerate(clause):
            _walk_when(item, errors, rels, cfgs, f"{prefix}[{idx}]")
        return
    if not isinstance(clause, dict):
        errors.append(f"{prefix}: when 절은 매핑이어야 함")
        return
    for k, v in clause.items():
        if k not in WHEN_CLAUSES:
            errors.append(f"{prefix}: 알 수 없는 when 절 '{k}'")
            continue
        if k == "not":
            _walk_when(v, errors, rels, cfgs, f"{prefix}.not")
        elif k in ("any", "all"):
            _walk_when(v, errors, rels, cfgs, f"{prefix}.{k}")
        elif k == "relation":
            if not isinstance(v, dict) or "type" not in v:
                errors.append(f"{prefix}.relation: type 필드 필요")
            else:
                rtype = v["type"]
                rels.add(rtype)
                if rtype not in RELATION_RULES:
                    errors.append(f"{prefix}.relation: 알 수 없는 관계 타입 '{rtype}'")
        elif k in ("config", "config_set"):
            if not isinstance(v, list) or len(v) < (3 if k == "config" else 2):
                errors.append(f"{prefix}.config: [$var, key, value] 형식 필요")
            else:
                ckey = v[1]
                cfgs.add(ckey)
                if ckey not in CONFIG_KEYS:
                    errors.append(f"{prefix}.config: 설정 키 사전에 없는 키 '{ckey}'")
        elif k == "reaches":
            rels.add("reaches")


def _validate_fact_items(items: Any, errors: list[str], loc: str) -> None:
    if not isinstance(items, list):
        errors.append(f"{loc}: 목록이어야 함")
        return
    for idx, item in enumerate(items):
        if isinstance(item, dict) and set(item.keys()) & {"any", "all"}:
            for key in ("any", "all"):
                if key in item:
                    _validate_fact_items(item[key], errors, f"{loc}[{idx}].{key}")
            continue
        expr = str(item).strip()
        m = FACT_RE.match(expr)
        if not m:
            errors.append(f"{loc}[{idx}]: 잘못된 Fact 형식 '{expr}'")
            continue
        if m.group(1) not in FACT_KINDS:
            errors.append(f"{loc}[{idx}]: 알 수 없는 Fact 종류 '{m.group(1)}'")


def load_rules(rules_dir: str | Path = RULES_DIR, files: list[str] | None = None) -> RuleValidationResult:
    """rules/*.yaml을 모두 읽어 규칙 형식과 IR 어휘·변수 바인딩 정합성을 검증한다.

    files를 주면 그 파일명(예: ["core.yaml"])만 읽는다.
    """
    base = Path(rules_dir)
    res = RuleValidationResult()
    seen_ids: set[str] = set()

    if not base.exists():
        res.errors.append(f"규칙 디렉터리 없음: {base}")
        return res

    for path in sorted(base.glob("*.yaml")):
        if files is not None and path.name not in files:
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or doc.get("rule_version") != "0.1":
            res.errors.append(f"{path.name}: rule_version '0.1' 필요")
            continue
        rules = doc.get("rules")
        if not isinstance(rules, list):
            res.errors.append(f"{path.name}: rules 목록 필요")
            continue

        for rule in rules:
            if not isinstance(rule, dict):
                res.errors.append(f"{path.name}: 규칙 항목은 매핑이어야 함")
                continue
            rid = rule.get("id")
            if not rid or not isinstance(rid, str):
                res.errors.append(f"{path.name}: 규칙 id 누락")
                continue
            if rid in seen_ids:
                res.errors.append(f"{path.name}: 중복 규칙 id '{rid}'")
                continue
            seen_ids.add(rid)

            for req_key in ("name", "category", "vars", "when", "requires", "adds", "probability"):
                if req_key not in rule:
                    res.errors.append(f"{rid}: 필수 필드 '{req_key}' 누락")

            cat = rule.get("category")
            if cat not in CATEGORIES:
                res.errors.append(f"{rid}: 잘못된 category '{cat}'")

            for tid in rule.get("attack_techniques") or []:
                if not TECH_RE.match(str(tid)):
                    res.errors.append(f"{rid}: 잘못된 ATT&CK 기법 ID '{tid}'")

            _validate_fact_items(rule.get("requires") or [], res.errors, f"{rid}.requires")
            _validate_fact_items(rule.get("adds") or [], res.errors, f"{rid}.adds")

            if "when" in rule:
                _walk_when(rule["when"], res.errors, res.referenced_relations, res.referenced_configs, f"{rid}.when")

            # 변수 선언 및 when 바인딩 검증
            for vname, vspec in (rule.get("vars") or {}).items():
                vtype = (vspec or {}).get("type", "asset")
                if vtype not in VAR_TYPES:
                    res.errors.append(f"{rid}: 변수 ${vname}의 알 수 없는 type '{vtype}'")
            declared_vars = set((rule.get("vars") or {}).keys())
            bound_vars = _collect_vars(rule.get("when"))
            used_vars = bound_vars | _collect_vars(rule.get("requires")) | _collect_vars(rule.get("adds"))
            for mod in (rule.get("probability") or {}).get("modifiers") or []:
                if isinstance(mod, dict) and "when" in mod:
                    used_vars |= _collect_vars(mod["when"])

            undeclared = used_vars - declared_vars
            if undeclared:
                res.errors.append(f"{rid}: vars에 선언되지 않은 변수 사용 {sorted(undeclared)}")

            unbound = (_collect_vars(rule.get("requires")) | _collect_vars(rule.get("adds"))) - bound_vars
            if unbound:
                res.errors.append(f"{rid}: when에서 바인딩되지 않은 변수 {sorted(unbound)}")

            prob = rule.get("probability") or {}
            base_dist = prob.get("base") or {}
            if base_dist.get("kind") != "beta" or base_dist.get("alpha", 0) <= 0 or base_dist.get("beta", 0) <= 0:
                res.errors.append(f"{rid}.probability.base: 양수 alpha/beta를 가진 beta 분포 필요")

            for idx, mod in enumerate(prob.get("modifiers") or []):
                if isinstance(mod, dict) and "when" in mod:
                    _walk_when(mod["when"], res.errors, res.referenced_relations, res.referenced_configs, f"{rid}.modifiers[{idx}]")

            res.rules.append(rule)

    return res
