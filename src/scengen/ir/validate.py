"""IR 검증: JSON Schema(구조) + 의미 검증(참조 무결성, 계층, 관계 타입, Attr 일관성).

오류(error)는 IR을 엔진에 넣을 수 없는 문제, 경고(warning)는 넣을 수는 있지만 의심스러운 것.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml
from jsonschema import Draft202012Validator

from .vocab import CONFIG_KEYS

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "ir.schema.json"

GROUP_PREFIX = "group:"

# 관계 타입별로 허용되는 (from, to) 노드 종류.
# 노드 종류: 자산은 asset.type, 그룹은 "group", 그룹 성격의 identity는 "identity_group".
ANY = None
RELATION_RULES: dict[str, tuple[set[str] | None, set[str] | None]] = {
    "reaches": (ANY, ANY),
    "routes_via": ({"group"}, {"network_device"}),
    "runs": ({"host"}, {"service", "software"}),
    "hosts": ({"host"}, {"host", "data_store"}),
    "member_of": ({"identity", "identity_group", "host"}, {"identity_group", "group"}),
    "has_permission": ({"identity", "identity_group", "external"}, ANY),  # external = 인터넷의 누구나
    "authenticates_to": ({"identity", "identity_group"}, {"service", "host"}),
    "session": ({"identity"}, {"host", "service"}),
    "stores": (ANY, {"credential", "data"}),
    "grants": ({"credential", "host", "service"}, {"identity", "identity_group"}),
    "contains": ({"data_store", "host", "service"}, {"data"}),
    "trusts": (ANY, ANY),
    "depends_on": (ANY, ANY),
    "manages": (ANY, ANY),  # 정책(policy) → 적용 대상 그룹·자산 포함
}

# 조건 리프에서 자산을 직접 가리키는 키
CONDITION_REF_KEYS = {
    "exfiltrated", "tampered", "destroyed", "disrupted", "misused",
    "read", "controls", "has_credential", "acts_as", "knows",
}


def profile_variants(profile: dict) -> list[dict[str, str]]:
    """공격자 프로필의 분석 변형 조합. 생략된 축은 두 값 모두 (기본 4개 변형)."""
    def values(key: str, default: tuple[str, ...]) -> list[str]:
        v = profile.get(key)
        if v is None:
            return list(default)
        return [v] if isinstance(v, str) else list(v)

    return [
        {"knowledge": k, "egress": e}
        for k in values("knowledge", ("informed", "uninformed"))
        for e in values("egress", ("assumed_open", "from_ir"))
    ]


@dataclass(frozen=True)
class Issue:
    level: str  # "error" | "warning"
    path: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.path}: {self.message}"


@dataclass
class ValidationResult:
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors


def _load_schema() -> dict[str, Any]:
    with SCHEMA_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def load_ir(path: str | Path) -> Any:
    with Path(path).open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _fmt_path(parts: Iterable[Any]) -> str:
    out = "$"
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else f".{p}"
    return out


# ---------------------------------------------------------------- 구조 검증

def _schema_issues(doc: Any) -> list[Issue]:
    validator = Draft202012Validator(_load_schema())
    issues = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        issues.append(Issue("error", _fmt_path(err.absolute_path), err.message))
    return issues


# ---------------------------------------------------------------- 의미 검증

class _Index:
    def __init__(self, doc: dict[str, Any], issues: list[Issue]):
        self.groups: dict[str, dict] = {}
        self.assets: dict[str, dict] = {}
        for i, g in enumerate(doc.get("groups") or []):
            self._add(self.groups, g, f"$.groups[{i}]", issues)
        for i, a in enumerate(doc.get("assets") or []):
            self._add(self.assets, a, f"$.assets[{i}]", issues)
        for gid in self.groups.keys() & self.assets.keys():
            issues.append(Issue("error", "$", f"id '{gid}'가 그룹과 자산에 동시에 쓰임"))

    @staticmethod
    def _add(table: dict, obj: dict, path: str, issues: list[Issue]) -> None:
        oid = obj["id"]
        if oid in table:
            issues.append(Issue("error", f"{path}.id", f"중복 id '{oid}'"))
        else:
            table[oid] = obj

    def node_kind(self, ref: str) -> str | None:
        """참조를 해석해 노드 종류를 돌려준다. 해석 불가면 None."""
        if ref.startswith(GROUP_PREFIX):
            return "group" if ref[len(GROUP_PREFIX):] in self.groups else None
        asset = self.assets.get(ref)
        if asset is None:
            return None
        if asset["type"] == "identity" and asset.get("kind") == "group":
            return "identity_group"
        return asset["type"]


def _check_ref(idx: _Index, ref: str, path: str, issues: list[Issue]) -> str | None:
    kind = idx.node_kind(ref)
    if kind is not None:
        return kind
    if not ref.startswith(GROUP_PREFIX) and ref in idx.groups:
        issues.append(Issue("error", path, f"'{ref}'는 그룹입니다. 'group:{ref}'로 참조하세요"))
    else:
        issues.append(Issue("error", path, f"존재하지 않는 참조 '{ref}'"))
    return None


def _check_groups(idx: _Index, doc: dict, issues: list[Issue]) -> None:
    for i, g in enumerate(doc.get("groups") or []):
        parent = g.get("parent")
        if parent is not None and parent not in idx.groups:
            issues.append(Issue("error", f"$.groups[{i}].parent", f"존재하지 않는 상위 그룹 '{parent}'"))
    # 순환 검사
    for gid in idx.groups:
        seen = {gid}
        cur = idx.groups[gid].get("parent")
        while cur is not None and cur in idx.groups:
            if cur in seen:
                issues.append(Issue("error", "$.groups", f"그룹 계층에 순환이 있음 ('{gid}'에서 시작)"))
                break
            seen.add(cur)
            cur = idx.groups[cur].get("parent")


def _check_assets(idx: _Index, doc: dict, issues: list[Issue]) -> None:
    for i, a in enumerate(doc.get("assets") or []):
        for j, gid in enumerate(a.get("groups") or []):
            if gid not in idx.groups:
                issues.append(Issue("error", f"$.assets[{i}].groups[{j}]", f"존재하지 않는 그룹 '{gid}'"))


def _check_relations(idx: _Index, doc: dict, issues: list[Issue]) -> None:
    for i, r in enumerate(doc.get("relations") or []):
        base = f"$.relations[{i}]"
        fk = _check_ref(idx, r["from"], f"{base}.from", issues)
        tk = _check_ref(idx, r["to"], f"{base}.to", issues)
        for key in ("via", "key_ref", "as"):
            if key in r:
                _check_ref(idx, r[key], f"{base}.{key}", issues)
        if "as" in r and idx.node_kind(r["as"]) not in (None, "identity"):
            issues.append(Issue("error", f"{base}.as", f"실행 계정 '{r['as']}'는 identity(사용자/서비스 계정)여야 함"))

        rule = RELATION_RULES.get(r["type"])
        if rule and fk and tk:
            allowed_from, allowed_to = rule
            if allowed_from is not None and fk not in allowed_from:
                issues.append(Issue("error", f"{base}.from",
                                    f"'{r['type']}'의 출발 노드로 '{fk}'는 허용되지 않음 (허용: {sorted(allowed_from)})"))
            if allowed_to is not None and tk not in allowed_to:
                issues.append(Issue("error", f"{base}.to",
                                    f"'{r['type']}'의 도착 노드로 '{tk}'는 허용되지 않음 (허용: {sorted(allowed_to)})"))

        if r["type"] == "member_of" and r["from"] == r["to"]:
            issues.append(Issue("error", base, "자기 자신에 대한 member_of"))
        if r["type"] != "reaches" and r["from"] == r["to"]:
            issues.append(Issue("warning", base, f"자기 자신을 가리키는 '{r['type']}' 관계"))


def _walk_condition(cond: Any, path: str, idx: _Index, issues: list[Issue]) -> None:
    if not isinstance(cond, dict):
        return
    for key in ("all", "any"):
        if key in cond:
            for j, sub in enumerate(cond[key]):
                _walk_condition(sub, f"{path}.{key}[{j}]", idx, issues)
            return
    for key, val in cond.items():
        if key in CONDITION_REF_KEYS and isinstance(val, str):
            _check_ref(idx, val, f"{path}.{key}", issues)
        elif key == "privilege" and isinstance(val, dict) and isinstance(val.get("asset"), str):
            _check_ref(idx, val["asset"], f"{path}.privilege.asset", issues)


def _check_goals_and_profiles(idx: _Index, doc: dict, issues: list[Issue]) -> None:
    goal_ids: set[str] = set()
    for i, g in enumerate(doc.get("impact_goals") or []):
        if g["id"] in goal_ids:
            issues.append(Issue("error", f"$.impact_goals[{i}].id", f"중복 목표 id '{g['id']}'"))
        goal_ids.add(g["id"])
        _walk_condition(g["condition"], f"$.impact_goals[{i}].condition", idx, issues)

    for i, p in enumerate(doc.get("attacker_profiles") or []):
        for j, ref in enumerate(p["start"]):
            _check_ref(idx, ref, f"$.attacker_profiles[{i}].start[{j}]", issues)

    ctx = doc.get("context") or {}
    for i, ks in enumerate(ctx.get("known_state") or []):
        _walk_condition(ks["fact"], f"$.context.known_state[{i}].fact", idx, issues)
    for i, ref in enumerate((ctx.get("scope") or {}).get("exclude") or []):
        _check_ref(idx, ref, f"$.context.scope.exclude[{i}]", issues)


def _iter_attr_objects(obj: Any, path: str):
    """source 키를 가진 dict를 모두 찾는다 (Attr 객체 또는 객체 단위 출처)."""
    if isinstance(obj, dict):
        if "source" in obj:
            yield obj, path
        for k, v in obj.items():
            yield from _iter_attr_objects(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _iter_attr_objects(v, f"{path}[{i}]")


def _check_distribution(dist: dict, path: str, issues: list[Issue]) -> None:
    kind = dist.get("kind")
    if kind == "categorical":
        total = sum(dist["p"].values())
        if abs(total - 1.0) > 0.01:
            issues.append(Issue("error", f"{path}.distribution", f"categorical 확률 합이 1이 아님 ({total:.3f})"))
    elif kind == "uniform" and dist["low"] > dist["high"]:
        issues.append(Issue("error", f"{path}.distribution", "uniform의 low > high"))


def _check_attrs(doc: dict, issues: list[Issue]) -> None:
    source_ids = {s["id"] for s in (doc.get("meta") or {}).get("sources") or []}
    for section in ("groups", "assets", "relations"):
        for attr, path in _iter_attr_objects(doc.get(section) or [], f"$.{section}"):
            src = attr.get("source")
            conf = attr.get("confidence")
            dist = attr.get("distribution")
            if src == "unknown" and attr.get("value") is not None:
                issues.append(Issue("error", path, "source가 unknown인데 value가 있음"))
            if src == "declared" and conf is not None and conf < 1.0:
                issues.append(Issue("warning", path, "declared인데 confidence < 1.0 (inferred가 맞는지 확인)"))
            if src == "inferred" and conf is None:
                issues.append(Issue("warning", path, "inferred 값에 confidence가 없음"))
            if src == "assumed" and conf is None and dist is None:
                issues.append(Issue("warning", path, "assumed 값에 confidence도 distribution도 없음 (엔진 기본 사전분포 사용)"))
            if dist is not None:
                if src in ("declared", "unknown"):
                    issues.append(Issue("warning", path, f"{src}인데 distribution이 있음 (assumed가 맞는지 확인)"))
                _check_distribution(dist, path, issues)
    # evidence가 소스 id처럼 보이는데 meta.sources에 없으면 경고
    if source_ids:
        for section in ("groups", "assets", "relations"):
            for i, obj in enumerate(doc.get(section) or []):
                ev = obj.get("evidence")
                if isinstance(ev, str) and " " not in ev and ":" not in ev and ev not in source_ids:
                    issues.append(Issue("warning", f"$.{section}[{i}].evidence",
                                        f"meta.sources에 없는 근거 id '{ev}'"))


def _check_config_block(config: dict, target: str, path: str, issues: list[Issue]) -> None:
    for key, raw in config.items():
        kpath = f"{path}.{key}"
        spec = CONFIG_KEYS.get(key)
        if spec is None:
            issues.append(Issue("warning", kpath, "설정 키 사전에 없는 키 (규칙이 읽지 못함)"))
            continue
        if spec.applies_to and target not in spec.applies_to:
            issues.append(Issue("warning", kpath,
                                f"'{target}'에는 맞지 않는 키 (붙일 수 있는 곳: {list(spec.applies_to)})"))
        value = raw.get("value") if isinstance(raw, dict) else raw
        problem = spec.check(value)
        if problem:
            issues.append(Issue("error", kpath, problem))


def _check_config(doc: dict, issues: list[Issue]) -> None:
    for i, g in enumerate(doc.get("groups") or []):
        _check_config_block(g.get("config") or {}, "group", f"$.groups[{i}].config", issues)
    for i, a in enumerate(doc.get("assets") or []):
        _check_config_block(a.get("config") or {}, a["type"], f"$.assets[{i}].config", issues)
    defaults = (doc.get("context") or {}).get("defaults") or {}
    _check_config_block(defaults, "context", "$.context.defaults", issues)


def _semantic_issues(doc: dict) -> list[Issue]:
    issues: list[Issue] = []
    idx = _Index(doc, issues)
    _check_groups(idx, doc, issues)
    _check_assets(idx, doc, issues)
    _check_relations(idx, doc, issues)
    _check_goals_and_profiles(idx, doc, issues)
    _check_attrs(doc, issues)
    _check_config(doc, issues)
    return issues


# ---------------------------------------------------------------- 진입점

def validate_ir(doc: Any) -> ValidationResult:
    result = ValidationResult()
    if not isinstance(doc, dict):
        result.issues.append(Issue("error", "$", "최상위가 객체(mapping)가 아님"))
        return result
    result.issues.extend(_schema_issues(doc))
    if result.errors:
        # 구조가 깨진 상태에서 의미 검증을 돌리면 연쇄 오류만 늘어난다.
        result.issues.append(Issue("warning", "$", "구조 오류가 있어 의미 검증을 건너뜀"))
        return result
    result.issues.extend(_semantic_issues(doc))
    return result


def validate_file(path: str | Path) -> ValidationResult:
    try:
        doc = load_ir(path)
    except yaml.YAMLError as e:
        result = ValidationResult()
        result.issues.append(Issue("error", "$", f"YAML 파싱 실패: {e}"))
        return result
    return validate_ir(doc)
