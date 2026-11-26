"""규칙셋(rules/*.yaml) 로드·문법·IR 어휘 정합성 검증 테스트 (WBS 2.3 / 2.4)."""

from scengen.rules import load_rules


def test_rules_load_and_validate():
    res = load_rules()
    assert res.ok, f"규칙 검증 오류: {res.errors}"
    ids = {r["id"] for r in res.rules}
    # 최소 규칙 R1~R11, R10b 및 discovery D2~D4 모두 포함
    expected = {f"R{i}" for i in range(1, 12)} | {"R10b", "D2", "D3", "D4"}
    assert expected <= ids
    # 확장 규칙(R12~R16) 포함
    assert {"R12", "R13", "R14", "R15", "R16"} <= ids
    # 규칙이 참조하는 관계·설정 키가 비어있지 않음
    assert len(res.referenced_relations) >= 8
    assert len(res.referenced_configs) >= 10
