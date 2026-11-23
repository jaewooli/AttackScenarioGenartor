"""참조 문서 대조표 공통 검사기 (WBS 1.6.2 ~ 1.6.5).

대조표 파일: src/scengen/ir/crosswalk/*.yaml
형식:
  reference, version, source, expected_count(선택), reasons(선택: 코드 → 설명)
  items: { <항목 id>: { label, status, ir?, how?, limit?, reason? , ... } }
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from .mitigations import LABEL, STATUSES
from .techniques import check_refs

DIR = Path(__file__).resolve().parent / "crosswalk"


@dataclass
class Report:
    name: str
    data: dict
    problems: list[str]
    status: Counter

    @property
    def passes(self) -> bool:
        return not self.problems and self.status.get("missing", 0) == 0


def names() -> list[str]:
    return sorted(p.stem for p in DIR.glob("*.yaml"))


def load(name: str) -> dict:
    return yaml.safe_load((DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def check(name: str) -> Report:
    data = load(name)
    items: dict = data.get("items") or {}
    reasons: dict = data.get("reasons") or {}
    problems: list[str] = []
    expected = data.get("expected_count")
    if expected is not None and len(items) != expected:
        problems.append(f"항목 수 {len(items)} ≠ 기대값 {expected}")
    for iid, e in items.items():
        owner = f"{name}:{iid}"
        st = e.get("status")
        if st not in STATUSES:
            problems.append(f"{owner}: status '{st}'가 올바르지 않음")
        if st in ("covered", "partial") and not e.get("ir"):
            problems.append(f"{owner}: 표현 가능하다면서 IR 요소가 없음")
        if st == "partial" and not e.get("limit"):
            problems.append(f"{owner}: partial인데 limit이 없음")
        if st == "out_of_scope":
            r = e.get("reason")
            if not r:
                problems.append(f"{owner}: 범위 밖인데 reason이 없음")
            elif reasons and r not in reasons:
                problems.append(f"{owner}: 정의되지 않은 reason 코드 '{r}'")
        problems += check_refs(owner, e.get("ir") or [])
    return Report(name, data, problems, Counter(e.get("status") for e in items.values()))


def render_markdown(name: str) -> str:
    r = check(name)
    d = r.data
    lines = [
        f"# {d['reference']} 대조표",
        "",
        f"> 생성된 문서다. 원본 `src/scengen/ir/crosswalk/{name}.yaml`을 고친 뒤",
        f"> `.venv/bin/scengen crosswalk {name} --markdown > docs/crosswalk/{name}.md`로 다시 만든다.",
        "",
    ]
    if d.get("question"):
        lines += [f"질문: **{d['question']}**", ""]
    lines += [
        f"- 기준: {d['reference']} {d.get('version', '')} — {d.get('source', '')}",
        f"- 항목 {sum(r.status.values())}개: " + " · ".join(f"{LABEL[s]} {r.status.get(s, 0)}" for s in STATUSES),
        f"- 통과 조건 (표현 불가 0): **{'통과' if r.passes else '미통과'}**",
    ]
    if d.get("notes"):
        lines += ["", *[f"> {n}" for n in d["notes"]]]
    if d.get("findings"):
        lines += ["", "## 대조 중 발견해서 보강한 빈틈", "", "| 빈틈 | 보강 | 관련 항목 |", "|---|---|---|"]
        lines += [f"| {f['gap']} | {f['fix']} | {', '.join(f.get('items', [])) or '—'} |" for f in d["findings"]]
    if d.get("reasons"):
        lines += ["", "## 범위 밖 사유 코드", "", "| 코드 | 의미 |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in d["reasons"].items()]
    extra_cols = d.get("extra_columns") or []
    lines += ["", "## 항목", "",
              "| 항목 | 요약 | " + "".join(f"{c} | " for c in extra_cols) + "상태 | IR 표현 | 설명 |",
              "|---|---|" + "---|" * len(extra_cols) + "---|---|---|"]
    for iid, e in d["items"].items():
        refs = ", ".join(f"`{x}`" for x in e.get("ir") or []) or "—"
        note = e.get("how", "")
        if e.get("limit"):
            note += f" **한계:** {e['limit']}"
        if e.get("reason"):
            note += f"사유: {e['reason']}"
        extras = "".join(f"{e.get(c, '')} | " for c in extra_cols)
        lines.append(f"| {iid} | {e.get('label', '')} | {extras}{LABEL.get(e.get('status'), '?')} | {refs} | {note} |")
    if r.problems:
        lines += ["", "## 검사 문제", ""] + [f"- {p}" for p in r.problems]
    return "\n".join(lines)


# ---------------------------------------------------------------- D3FEND (WBS 1.6.3)

D3FEND_MAP = Path(__file__).resolve().parent / "crosswalk_d3fend.yaml"
D3FEND_DATA = Path(__file__).resolve().parent.parent / "data" / "d3fend-techniques.json"


def d3fend_check() -> Report:
    import json

    data = yaml.safe_load(D3FEND_MAP.read_text(encoding="utf-8"))
    official = json.loads(D3FEND_DATA.read_text(encoding="utf-8"))["techniques"]
    by_id = {t["id"]: t for t in official}
    items: dict = data.get("items") or {}
    reasons: dict = data.get("reasons") or {}
    must = set(data.get("must_map_tactics") or [])
    problems: list[str] = []

    for iid in items:
        if iid not in by_id:
            problems.append(f"d3fend:{iid}: 공식 목록에 없는 기법")

    def resolve(t: dict) -> tuple[dict | None, str]:
        cur = t
        while cur is not None:
            if cur["id"] in items:
                return items[cur["id"]], "개별" if cur is t else f"상위({cur['id']})"
            cur = by_id.get(cur["parent"]) if cur.get("parent") else None
        d = (data.get("defaults_by_tactic") or {}).get(t["tactic"])
        return d, "전술 기본값"

    status: Counter = Counter()
    resolved: dict[str, tuple[dict, str]] = {}
    for t in official:
        if t["tactic"] in must and t["level"] <= 1 and t["id"] not in items:
            problems.append(f"d3fend:{t['id']} {t['name']}: 인프라 상태 전술인데 개별 대조되지 않음")
        e, how = resolve(t)
        if e is None:
            problems.append(f"d3fend:{t['id']}: 분류되지 않음")
            continue
        resolved[t["id"]] = (e, how)
        status[e.get("status")] += 1

    for owner, e in list(items.items()) + [(f"기본값({k})", v) for k, v in (data.get("defaults_by_tactic") or {}).items()]:
        o = f"d3fend:{owner}"
        st = e.get("status")
        if st not in STATUSES:
            problems.append(f"{o}: status '{st}'가 올바르지 않음")
        if st in ("covered", "partial") and not e.get("ir"):
            problems.append(f"{o}: 표현 가능하다면서 IR 요소가 없음")
        if st == "partial" and not e.get("limit"):
            problems.append(f"{o}: partial인데 limit이 없음")
        if st == "out_of_scope" and e.get("reason") not in reasons:
            problems.append(f"{o}: reason 코드가 없거나 정의되지 않음")
        problems += check_refs(o, e.get("ir") or [])

    data["_resolved"] = resolved
    data["_official"] = official
    return Report("d3fend", data, problems, status)


def d3fend_markdown() -> str:
    r = d3fend_check()
    d = r.data
    tactics = Counter(t["tactic"] for t in d["_official"])
    lines = [
        "# MITRE D3FEND 대조표 (WBS 1.6.3)",
        "",
        "> 생성된 문서다. 원본 `src/scengen/ir/crosswalk_d3fend.yaml`을 고친 뒤",
        "> `.venv/bin/scengen crosswalk d3fend --markdown > docs/crosswalk/d3fend.md`로 다시 만든다.",
        "",
        "질문: **\"이 방어 기법이 적용되어 있는지를 IR로 표현할 수 있는가?\"**",
        "",
        f"- 기준: MITRE D3FEND 기법 {len(d['_official'])}개 (전술별: "
        + ", ".join(f"{k} {v}" for k, v in tactics.items()) + ")",
        "- Model·Harden·Isolate 의 0·1단계는 개별 대조, 2단계는 상위 기법을 물려받음, Detect·Deceive·Evict·Restore 는 전술 기본값",
        "- 상태: " + " · ".join(f"{LABEL[s]} {r.status.get(s, 0)}" for s in STATUSES),
        f"- 통과 조건 (표현 불가 0): **{'통과' if r.passes else '미통과'}**",
        "",
        "## 대조 중 발견해서 보강한 빈틈",
        "",
        "| 빈틈 | 보강 | 관련 기법 |",
        "|---|---|---|",
        *[f"| {f['gap']} | {f['fix']} | {', '.join(f['items'])} |" for f in d.get("findings") or []],
        "",
        "## 범위 밖 사유 코드",
        "",
        "| 코드 | 의미 |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in d["reasons"].items()],
        "",
        "## 기법별 결과",
        "",
        "| 기법 | 이름 | 전술 | 단계 | 근거 | 상태 | IR 표현 | 설명 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for t in d["_official"]:
        if t["id"] not in d["_resolved"]:
            continue
        e, how = d["_resolved"][t["id"]]
        refs = ", ".join(f"`{x}`" for x in e.get("ir") or []) or "—"
        note = e.get("how", "")
        if e.get("limit"):
            note += f" **한계:** {e['limit']}"
        if e.get("reason"):
            note += f"사유: {e['reason']}"
        lines.append(f"| {t['id']} | {t['name']} | {t['tactic']} | {t['level']} | {how} | "
                     f"{LABEL.get(e.get('status'), '?')} | {refs} | {note} |")
    if r.problems:
        lines += ["", "## 검사 문제", ""] + [f"- {p}" for p in r.problems]
    return "\n".join(lines)
