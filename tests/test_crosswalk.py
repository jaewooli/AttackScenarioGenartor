"""WBS 1.6 참조 문서 대조 검증."""

from pathlib import Path

from scengen.ir import techniques

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------ 1.6.1 ATT&CK 공격 기법

def test_technique_crosswalk_passes():
    report = techniques.check()
    assert not report.problems, report.problems
    assert report.status.get("missing", 0) == 0


def test_every_technique_is_classified():
    report = techniques.check()
    total = len(techniques.load_official()["techniques"])
    assert sum(report.roles.values()) == total == 227


def test_state_changing_techniques_are_mapped_individually():
    official = techniques.load_official()
    mapping = techniques.load_map()
    for t in official["techniques"]:
        if techniques.STATE_TACTICS & set(t["tactics"]):
            _, explicit = techniques.resolve(t, mapping)
            assert explicit, f"{t['id']} {t['name']}"


def test_technique_doc_is_up_to_date():
    path = ROOT / "docs" / "crosswalk" / "attack-techniques.md"
    assert path.read_text(encoding="utf-8") == techniques.render_markdown() + "\n"


# ------------------------------------------------------------ 1.6.2 ~ 1.6.5

import pytest

from scengen.ir import crosswalks


@pytest.mark.parametrize("name, expected", [
    ("cis-controls-v8.1", 153),
    ("platform-baselines", 124),
    ("governance-application", 70),
])
def test_crosswalk_passes(name, expected):
    r = crosswalks.check(name)
    assert not r.problems, r.problems
    assert r.status.get("missing", 0) == 0
    assert sum(r.status.values()) == expected


def test_d3fend_passes_and_classifies_everything():
    r = crosswalks.d3fend_check()
    assert not r.problems, r.problems
    assert r.status.get("missing", 0) == 0
    assert sum(r.status.values()) == len(r.data["_official"]) == 271


@pytest.mark.parametrize("name", ["cis-controls-v8.1", "platform-baselines", "governance-application", "d3fend"])
def test_crosswalk_doc_is_up_to_date(name):
    md = crosswalks.d3fend_markdown() if name == "d3fend" else crosswalks.render_markdown(name)
    assert (ROOT / "docs" / "crosswalk" / f"{name}.md").read_text(encoding="utf-8") == md + "\n"


def test_cis_map_carries_no_source_titles():
    # 라이선스: CIS 원문 제목을 저장하지 않는다 (요약은 한국어 자체 작성)
    items = crosswalks.load("cis-controls-v8.1")["items"]
    for iid, e in items.items():
        assert not any(c.isascii() and c.isalpha() for c in e["label"].replace("DNS", "").replace("DHCP", "")
                       .replace("DMARC", "").replace("VPN", "").replace("URL", "")), (iid, e["label"])
