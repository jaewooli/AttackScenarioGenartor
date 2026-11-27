"""규칙셋(src/scengen/rules/*.yaml) 로드·문법·IR 어휘·변수 바인딩 정합성 검증 테스트 (WBS 2.3 / 2.4)."""

from scengen.rules import load_rules


def test_rules_load_and_validate():
    res = load_rules()
    assert res.ok, f"규칙 검증 오류: {res.errors}"
    ids = {r["id"] for r in res.rules}
    # 최소 규칙 R1~R11(R3/R9 분해 포함), R10b 및 discovery D2~D4 모두 포함
    expected = {
        "D2", "D3", "D4",
        "R1", "R2",
        "R3-data-read", "R3-data-read-encrypted", "R3-data-write",
        "R3-host", "R3-policy", "R3-identity", "R3-group",
        "R4", "R5", "R6", "R7", "R8",
        "R9-direct", "R9-hosted", "R9-hosted-encrypted",
        "R10", "R10-managed", "R10b", "R11",
    }
    assert expected <= ids
    # 확장 규칙(R12~R16) 포함
    assert {"R12", "R13", "R14", "R15", "R16"} <= ids
    # 규칙이 참조하는 관계·설정 키가 비어있지 않음
    assert len(res.referenced_relations) >= 8
    assert len(res.referenced_configs) >= 10


def test_loader_rejects_unbound_variable(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        """
rule_version: "0.1"
rules:
  - id: R-BAD
    name: "미바인딩 테스트"
    category: transition
    vars:
      a: { type: asset }
      b: { type: asset }
    when:
      - asset_type: { asset: $a, type: host }
    requires:
      - foothold($a, user)
    adds:
      - foothold($b, admin)
    probability:
      base: { kind: beta, alpha: 1.0, beta: 1.0 }
""",
        encoding="utf-8",
    )
    res = load_rules(tmp_path)
    assert not res.ok
    assert any("바인딩되지 않은 변수" in e for e in res.errors)
