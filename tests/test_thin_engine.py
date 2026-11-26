"""얇은 엔진(R1~R11) 단위 테스트 및 shop-hybrid 샘플 검증."""

from pathlib import Path

from scengen.engine import Fact, InfraGraph, analyze_doc, run_variant
from scengen.ir import load_ir

SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "samples"


def test_shop_hybrid_variants_and_goals():
    doc = load_ir(SAMPLES / "shop-hybrid.ir.yaml")
    results = analyze_doc(doc)
    # external(4변형) + insider(knowledge=informed 고정 -> egress 2변형) = 6개 변형
    assert len(results) == 6

    ext_inf_open = next(
        r for r in results if r.profile_id == "external" and r.knowledge == "informed" and r.egress == "assumed_open"
    )
    ext_uninf_open = next(
        r for r in results if r.profile_id == "external" and r.knowledge == "uninformed" and r.egress == "assumed_open"
    )

    goals_inf = {g.goal_id: g for g in ext_inf_open.goals}
    goals_uninf = {g.goal_id: g for g in ext_uninf_open.goals}
    assert goals_inf["goal-customer-exfil"].achieved
    assert goals_inf["goal-combined-exfil"].achieved
    assert goals_inf["goal-shop-down"].achieved
    # uninformed 변형은 정찰(knows) 전제 때문에 확률이 informed보다 낮아야 함
    assert goals_uninf["goal-customer-exfil"].prob < goals_inf["goal-customer-exfil"].prob


def test_egress_from_ir_blocks_when_no_external_path():
    doc = load_ir(SAMPLES / "shop-hybrid.ir.yaml")
    # vpc-prod -> ext-internet 유출 엣지 제거
    doc["relations"] = [
        r for r in doc["relations"]
        if not (r["type"] == "reaches" and r["from"] == "group:vpc-prod" and r["to"] == "ext-internet")
    ]
    graph = InfraGraph(doc)
    prof = doc["attacker_profiles"][0]
    res_open = run_variant(graph, prof, "informed", "assumed_open")
    res_ir = run_variant(graph, prof, "informed", "from_ir")

    assert any(g.goal_id == "goal-customer-exfil" and g.achieved for g in res_open.goals)
    assert any(g.goal_id == "goal-customer-exfil" and not g.achieved for g in res_ir.goals)


def test_r1_to_r8_r11_chain():
    """R6(보관 자격증명) -> R7(자격증명 사용) -> R1(그룹 소속) -> R3(권한 사용) -> R11(정책 관리) 연쇄 검증."""
    doc = {
        "ir_version": "0.2",
        "groups": [{"id": "g-net", "kind": "subnet"}],
        "assets": [
            {"id": "ext", "type": "external"},
            {"id": "h1", "type": "host", "role": "web_server", "groups": ["g-net"]},
            {"id": "svc1", "type": "service", "kind": "web_app", "port": 80, "protocol": "tcp"},
            {"id": "cred1", "type": "credential", "kind": "token"},
            {"id": "u1", "type": "identity", "kind": "user"},
            {"id": "grp1", "type": "identity", "kind": "group"},
            {"id": "pol1", "type": "policy", "kind": "directory_policy"},
            {"id": "h2", "type": "host", "role": "db_server"},
            {"id": "st2", "type": "data_store", "role": "db_server"},
            {"id": "d2", "type": "data", "categories": ["personal"]},
        ],
        "relations": [
            {"type": "reaches", "from": "ext", "to": "h1", "ports": [80]},
            {"type": "runs", "from": "h1", "to": "svc1"},
            {"type": "stores", "from": "h1", "to": "cred1"},
            {"type": "grants", "from": "cred1", "to": "u1"},
            {"type": "member_of", "from": "u1", "to": "grp1"},
            {"type": "has_permission", "from": "grp1", "to": "pol1", "action": "write", "effect": "allow"},
            {"type": "manages", "from": "pol1", "to": "h2"},
            {"type": "hosts", "from": "h2", "to": "st2"},
            {"type": "contains", "from": "st2", "to": "d2"},
        ],
    }
    res = run_variant(InfraGraph(doc), {"id": "ext", "start": ["ext"]}, "informed", "assumed_open")
    assert Fact.has_credential("cred1") in res.facts
    assert Fact.acts_as("u1") in res.facts
    assert Fact.acts_as("grp1") in res.facts
    assert Fact.foothold("pol1", "admin") in res.facts
    assert Fact.foothold("h2", "admin") in res.facts
    assert Fact.data_access("d2", "read") in res.facts


def test_deny_overrides_allow_and_encrypted_requires_key():
    doc = {
        "ir_version": "0.2",
        "assets": [
            {"id": "ext", "type": "external"},
            {"id": "st", "type": "data_store", "role": "backup"},
            {"id": "d1", "type": "data", "categories": ["personal"]},
            {"id": "k1", "type": "credential", "kind": "key"},
        ],
        "relations": [
            {"type": "contains", "from": "st", "to": "d1", "encrypted": True, "key_ref": "k1"},
            {"type": "has_permission", "from": "ext", "to": "st", "action": "read", "effect": "allow"},
            {"type": "has_permission", "from": "ext", "to": "st", "action": "read", "effect": "deny"},
        ],
    }
    res = run_variant(InfraGraph(doc), {"id": "ext", "start": ["ext"]}, "informed", "assumed_open")
    assert Fact.data_access("d1", "read") not in res.facts
