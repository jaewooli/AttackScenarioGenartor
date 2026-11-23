"""MITRE ATT&CK 완화책 대조표 검사와 문서 생성.

- 대조표 원본: mitigation_map.yaml
- 공식 목록: ../data/attack-mitigations.json (attack-stix-data에서 추출)
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from .fields import schema_fields
from .validate import SCHEMA_PATH
from .vocab import CONFIG_KEYS

HERE = Path(__file__).resolve().parent
MAP_PATH = HERE / "mitigation_map.yaml"
OFFICIAL_PATH = HERE.parent / "data" / "attack-mitigations.json"

STATUSES = ("covered", "partial", "missing", "out_of_scope")
LABEL = {"covered": "✅ 표현 가능", "partial": "⚠️ 일부", "missing": "❌ 불가", "out_of_scope": "➖ 범위 밖"}


@dataclass
class Report:
    problems: list[str]
    initial: Counter
    current: Counter

    @property
    def passes_gate(self) -> bool:
        """M0.5 통과 조건: 문제 없음 + 표현 불가 0개."""
        return not self.problems and self.current.get("missing", 0) == 0


def load_official() -> dict:
    return json.loads(OFFICIAL_PATH.read_text(encoding="utf-8"))


def load_map() -> dict:
    return yaml.safe_load(MAP_PATH.read_text(encoding="utf-8"))


def _relation_types() -> set[str]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return set(schema["$defs"]["relation"]["properties"]["type"]["enum"])


def check() -> Report:
    official = load_official()
    mapping = load_map()
    entries: dict = mapping.get("mitigations") or {}
    problems: list[str] = []

    if str(mapping.get("attack_version")) != str(official["attack_version"]):
        problems.append(f"대조표 ATT&CK 버전 {mapping.get('attack_version')} ≠ 공식 목록 {official['attack_version']}")

    official_ids = {m["id"] for m in official["mitigations"]}
    for mid in sorted(official_ids - entries.keys()):
        problems.append(f"{mid}: 대조표에 없음")
    for mid in sorted(entries.keys() - official_ids):
        problems.append(f"{mid}: 공식 목록에 없는 완화책 (폐기되었는지 확인)")

    fields = schema_fields()
    rel_types = _relation_types()
    for mid, e in entries.items():
        for key in ("initial", "status"):
            if e.get(key) not in STATUSES:
                problems.append(f"{mid}: {key} 값 '{e.get(key)}'가 올바르지 않음")
        status = e.get("status")
        refs = e.get("ir") or []
        if status in ("covered", "partial") and not refs:
            problems.append(f"{mid}: 표현 가능하다면서 IR 요소가 없음")
        if status == "partial" and not e.get("limit"):
            problems.append(f"{mid}: partial인데 limit(표현 못 하는 부분)이 없음")
        if status == "out_of_scope" and not e.get("reason"):
            problems.append(f"{mid}: 범위 밖인데 reason이 없음")
        for ref in refs:
            kind, _, name = ref.partition(":")
            ok = (
                (kind == "config" and name in CONFIG_KEYS)
                or (kind == "relation" and name in rel_types)
                or (kind == "field" and name in fields)
            )
            if not ok:
                problems.append(f"{mid}: IR에 없는 요소 '{ref}'")

    return Report(
        problems=problems,
        initial=Counter(e.get("initial") for e in entries.values()),
        current=Counter(e.get("status") for e in entries.values()),
    )


def unused_config_keys() -> list[str]:
    """어떤 완화책에도 연결되지 않은 설정 키 (정보용)."""
    used = {
        ref.split(":", 1)[1]
        for e in (load_map().get("mitigations") or {}).values()
        for ref in e.get("ir") or []
        if ref.startswith("config:")
    }
    return sorted(set(CONFIG_KEYS) - used)


def render_markdown() -> str:
    official = load_official()
    entries = load_map()["mitigations"]
    report = check()

    def counts(c: Counter) -> str:
        return " · ".join(f"{LABEL[s]} {c.get(s, 0)}" for s in STATUSES)

    lines = [
        "# MITRE ATT&CK 완화책 대조표",
        "",
        "> 이 파일은 생성된 문서다. 직접 고치지 말고 `src/scengen/ir/mitigation_map.yaml`을 고친 뒤",
        "> `.venv/bin/scengen mitigations --markdown > docs/mitigation-coverage.md`로 다시 만든다.",
        "",
        "질문: **\"이 완화책이 적용되어 있는지를 IR로 표현할 수 있는가?\"**",
        "",
        f"- 기준: {official['source']}, ATT&CK v{official['attack_version']} (가져온 날 {official['retrieved']}), 활성 완화책 {len(official['mitigations'])}개",
        f"- 첫 대조 (IR v0.2, 보강 전): {counts(report.initial)}",
        f"- 현재: {counts(report.current)}",
        f"- M0.5 통과 조건 (표현 불가 0, 범위 밖은 사유 기록): **{'통과' if report.passes_gate else '미통과'}**",
        "",
        "막는 기법 수 = 이 완화책이 막는 ATT&CK 기법·하위 기법의 수. 많을수록 표현이 중요하다.",
        "",
        "| 완화책 | 이름 | 막는 기법 수 | 처음 | 현재 | IR 표현 | 설명 |",
        "|---|---|---|---|---|---|---|",
    ]
    for m in sorted(official["mitigations"], key=lambda m: -m["techniques"]):
        e = entries.get(m["id"], {})
        refs = ", ".join(f"`{r}`" for r in e.get("ir") or []) or "—"
        note = e.get("how", "")
        if e.get("limit"):
            note += f" **한계:** {e['limit']}"
        if e.get("reason"):
            note += f"사유: {e['reason']}"
        lines.append(
            f"| [{m['id']}]({m['url']}) | {m['name']} | {m['techniques']} | "
            f"{LABEL.get(e.get('initial'), '?')} | {LABEL.get(e.get('status'), '?')} | {refs} | {note} |"
        )
    unused = unused_config_keys()
    lines += [
        "",
        "## 완화책에 연결되지 않은 설정 키",
        "",
        ("없음" if not unused else ", ".join(f"`{k}`" for k in unused)
         + " — 완화책이 아니라 공격 표면(취약 상태)을 나타내는 키"),
        "",
    ]
    if report.problems:
        lines += ["## 검사 문제", ""] + [f"- {p}" for p in report.problems] + [""]
    return "\n".join(lines)
