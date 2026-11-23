"""M0.5: MITRE ATT&CK 완화책 대조표 검증.

1. 공식 목록의 모든 완화책이 대조표에 있고, 표현 불가가 0개다.
2. 대조표가 가리키는 IR 요소(설정 키, 관계, 필드)가 실제로 존재한다.
3. "표현 가능"이 이름뿐이 아니다: 대조표가 쓰는 모든 설정 키를 실제 IR 샘플에 써넣었고, 그 샘플이 검증을 통과한다.
4. 생성 문서(docs/mitigation-coverage.md)가 원본과 일치한다.
"""

from pathlib import Path

import yaml

from scengen.cli import main
from scengen.ir import validate_file
from scengen.ir.mitigations import check, load_map, load_official, render_markdown
from scengen.ir.vocab import CONFIG_KEYS

ROOT = Path(__file__).resolve().parents[1]
SHOP = ROOT / "docs" / "samples" / "shop-hybrid.ir.yaml"
DOC = ROOT / "docs" / "mitigation-coverage.md"


def test_official_list_is_complete_snapshot():
    official = load_official()
    ids = [m["id"] for m in official["mitigations"]]
    assert len(ids) == len(set(ids)) == 44
    assert official["attack_version"] == "20.1"


def test_mitigation_map_passes_gate():
    report = check()
    assert not report.problems, report.problems
    assert report.current.get("missing", 0) == 0
    assert report.passes_gate


def _config_keys_used_in(path: Path) -> set[str]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    used = set((doc.get("context") or {}).get("defaults") or {})
    for section in ("groups", "assets"):
        for obj in doc.get(section) or []:
            used |= set(obj.get("config") or {})
    return used


def test_every_mapped_config_key_is_written_in_a_real_sample():
    mapped = {
        ref.split(":", 1)[1]
        for e in load_map()["mitigations"].values()
        if e["status"] in ("covered", "partial")
        for ref in e.get("ir") or []
        if ref.startswith("config:")
    }
    missing = mapped - _config_keys_used_in(SHOP)
    assert not missing, f"샘플에 써보지 않은 설정 키: {sorted(missing)}"


def test_shop_sample_is_clean():
    result = validate_file(SHOP)
    assert not result.issues, [str(i) for i in result.issues]


def test_every_config_key_in_vocab_is_exercised():
    # 사전의 모든 키가 최소 한 번은 실제 IR에 쓰였는지 (안 쓰인 키는 형식 오류가 숨어 있을 수 있음)
    unused = set(CONFIG_KEYS) - _config_keys_used_in(SHOP)
    assert not unused, f"샘플에서 한 번도 쓰이지 않은 키: {sorted(unused)}"


def test_generated_doc_is_up_to_date():
    assert DOC.read_text(encoding="utf-8") == render_markdown() + "\n", (
        "docs/mitigation-coverage.md 가 오래됨: "
        ".venv/bin/scengen mitigations --markdown > docs/mitigation-coverage.md")


def test_config_key_doc_is_up_to_date():
    from scengen.ir.vocab import render_markdown as render_vocab

    path = ROOT / "docs" / "config-keys.md"
    assert path.read_text(encoding="utf-8") == render_vocab() + "\n", (
        "docs/config-keys.md 가 오래됨: .venv/bin/scengen vocab --markdown > docs/config-keys.md")


def test_cli_mitigations(capsys):
    assert main(["mitigations"]) == 0
    assert "통과" in capsys.readouterr().out


def test_yaml_boolean_trap_hint():
    from scengen.ir import validate_ir

    doc = yaml.safe_load("""
ir_version: "0.2"
assets:
  - id: h1
    type: host
    config: { host.firewall: on }
""")
    result = validate_ir(doc)
    assert any("따옴표" in i.message for i in result.errors)
