"""MITRE ATT&CK 공격 기법 대조표 검사와 문서 생성 (WBS 1.6.1).

- 대조표 원본: technique_map.yaml
- 공식 목록: ../data/attack-techniques.json (상위 기법)
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from .mitigations import LABEL, STATUSES, _relation_types
from .fields import schema_fields
from .vocab import CONFIG_KEYS

HERE = Path(__file__).resolve().parent
MAP_PATH = HERE / "technique_map.yaml"
OFFICIAL_PATH = HERE.parent / "data" / "attack-techniques.json"

ROLES = ("transition", "goal", "discovery", "in_foothold", "state_neutral", "pre")
ROLE_LABEL = {
    "transition": "상태 전이", "goal": "목표(피해)", "discovery": "발견",
    "in_foothold": "거점 내 행위", "state_neutral": "상태 불변", "pre": "공격 전",
}
# 이 전술을 가진 기법은 기본값으로 넘기지 말고 반드시 개별 대조해야 한다
STATE_TACTICS = {
    "initial-access", "lateral-movement", "privilege-escalation", "credential-access",
    "collection", "exfiltration", "impact",
}


@dataclass
class Report:
    problems: list[str]
    status: Counter
    roles: Counter
    explicit: int

    @property
    def passes(self) -> bool:
        return not self.problems and self.status.get("missing", 0) == 0


def load_official() -> dict:
    return json.loads(OFFICIAL_PATH.read_text(encoding="utf-8"))


def load_map() -> dict:
    return yaml.safe_load(MAP_PATH.read_text(encoding="utf-8"))


def resolve(tech: dict, mapping: dict) -> tuple[dict | None, bool]:
    """(대조 항목, 개별 대조 여부). 해당 없음이면 (None, False)."""
    entry = (mapping.get("techniques") or {}).get(tech["id"])
    if entry is not None:
        return entry, True
    for d in mapping.get("defaults_by_tactic") or []:
        if d["tactic"] in tech["tactics"]:
            return d, False
    return None, False


def check_refs(owner: str, refs: list[str]) -> list[str]:
    fields = schema_fields()
    rel_types = _relation_types()
    bad = []
    for ref in refs:
        kind, _, name = ref.partition(":")
        ok = (
            (kind == "config" and name in CONFIG_KEYS)
            or (kind == "relation" and name in rel_types)
            or (kind == "field" and name in fields)
        )
        if not ok:
            bad.append(f"{owner}: IR에 없는 요소 '{ref}'")
    return bad


def _check_entry(owner: str, e: dict) -> list[str]:
    problems = []
    if e.get("role") not in ROLES:
        problems.append(f"{owner}: role '{e.get('role')}'가 올바르지 않음")
    if e.get("status") not in STATUSES:
        problems.append(f"{owner}: status '{e.get('status')}'가 올바르지 않음")
    if e.get("role") in ("transition", "goal") and not e.get("ir"):
        problems.append(f"{owner}: 상태를 바꾸는 기법인데 IR 요소가 없음")
    if e.get("status") == "partial" and not e.get("limit"):
        problems.append(f"{owner}: partial인데 limit이 없음")
    if e.get("status") == "out_of_scope" and not e.get("reason"):
        problems.append(f"{owner}: 범위 밖인데 reason이 없음")
    problems += check_refs(owner, e.get("ir") or [])
    return problems


def check() -> Report:
    official = load_official()
    mapping = load_map()
    problems: list[str] = []
    if str(mapping.get("attack_version")) != str(official["attack_version"]):
        problems.append(f"대조표 ATT&CK 버전 {mapping.get('attack_version')} ≠ 공식 목록 {official['attack_version']}")

    for d in mapping.get("defaults_by_tactic") or []:
        problems += _check_entry(f"기본값({d['tactic']})", d)
    explicit_ids = set((mapping.get("techniques") or {}).keys())
    official_ids = {t["id"] for t in official["techniques"]}
    for tid in sorted(explicit_ids - official_ids):
        problems.append(f"{tid}: 공식 목록에 없는 기법 (폐기·하위 기법인지 확인)")

    status, roles = Counter(), Counter()
    for t in official["techniques"]:
        entry, is_explicit = resolve(t, mapping)
        if entry is None:
            problems.append(f"{t['id']}: 분류되지 않음 (전술 {t['tactics']})")
            continue
        if not is_explicit and STATE_TACTICS & set(t["tactics"]):
            problems.append(f"{t['id']} {t['name']}: 상태를 바꾸는 전술인데 개별 대조되지 않음")
        if is_explicit:
            problems += _check_entry(t["id"], entry)
        status[entry.get("status")] += 1
        roles[entry.get("role")] += 1

    return Report(problems=problems, status=status, roles=roles, explicit=len(explicit_ids))


def render_markdown() -> str:
    official = load_official()
    mapping = load_map()
    report = check()

    lines = [
        "# MITRE ATT&CK 공격 기법 대조표 (WBS 1.6.1)",
        "",
        "> 생성된 문서다. 직접 고치지 말고 `src/scengen/ir/technique_map.yaml`을 고친 뒤",
        "> `.venv/bin/scengen techniques --markdown > docs/crosswalk/attack-techniques.md`로 다시 만든다.",
        "",
        "질문: **\"이 기법이 가능하려면 필요한 인프라 상태를 IR로 표현할 수 있는가?\"**",
        "추상 수준만 다룬다. 전제가 되는 인프라 상태만 적고 실행 방법은 적지 않는다.",
        "",
        f"- 기준: {official['source']}, ATT&CK v{official['attack_version']}, 상위 기법 {len(official['techniques'])}개",
        f"- 개별 대조 {report.explicit}개, 나머지는 전술별 기본 분류",
        "- 역할: " + " · ".join(f"{ROLE_LABEL[r]} {report.roles.get(r, 0)}" for r in ROLES),
        "- 상태: " + " · ".join(f"{LABEL[s]} {report.status.get(s, 0)}" for s in STATUSES),
        f"- 통과 조건 (표현 불가 0): **{'통과' if report.passes else '미통과'}**",
        "",
        "## 대조 중 발견해서 보강한 빈틈",
        "",
        "| 빈틈 | 보강 | 관련 기법 |",
        "|---|---|---|",
        *[f"| {f['gap']} | {f['fix']} | {', '.join(f['techniques']) or '—'} |" for f in mapping.get("findings") or []],
        "",
        "## 전술별 기본 분류",
        "",
        "| 전술 | 역할 | 상태 | IR 표현 | 설명 |",
        "|---|---|---|---|---|",
    ]
    for d in mapping["defaults_by_tactic"]:
        refs = ", ".join(f"`{r}`" for r in d.get("ir") or []) or "—"
        note = d.get("how") or f"사유: {d.get('reason', '')}"
        lines.append(f"| {d['tactic']} | {ROLE_LABEL[d['role']]} | {LABEL[d['status']]} | {refs} | {note} |")

    lines += [
        "",
        "## 개별 대조 (공격자 상태를 바꾸거나 피해를 내는 기법)",
        "",
        "사용 기록 = 이 기법을 쓴 것으로 ATT&CK에 기록된 그룹·소프트웨어·캠페인 관계 수.",
        "",
        "| 기법 | 이름 | 사용 기록 | 역할 | 상태 | IR 표현 | 설명 |",
        "|---|---|---|---|---|---|---|",
    ]
    by_id = {t["id"]: t for t in official["techniques"]}
    explicit = mapping.get("techniques") or {}
    for tid in sorted(explicit, key=lambda i: (ROLES.index(explicit[i]["role"]), -by_id[i]["uses"])):
        e, t = explicit[tid], by_id[tid]
        refs = ", ".join(f"`{r}`" for r in e.get("ir") or []) or "—"
        note = e.get("how", "")
        if e.get("limit"):
            note += f" **한계:** {e['limit']}"
        lines.append(f"| [{tid}]({t['url']}) | {t['name']} | {t['uses']} | {ROLE_LABEL[e['role']]} | "
                     f"{LABEL[e['status']]} | {refs} | {note} |")
    if report.problems:
        lines += ["", "## 검사 문제", ""] + [f"- {p}" for p in report.problems]
    return "\n".join(lines)
