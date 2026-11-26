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


def test_goad_auto_profile_and_dc_controls():
    """attacker_profiles와 external이 없는 GOAD 샘플에서도 자동 내부자 후보로 분석이 동작해야 한다."""
    doc = load_ir(SAMPLES / "goad-infra.ir.yaml")
    results = analyze_doc(doc)
    assert len(results) == 4
    inf = next(r for r in results if r.knowledge == "informed" and r.egress == "assumed_open")
    assert inf.profile_id == "insider-auto"
    assert len(inf.facts) > 0
    # net-lab 내 R10 + R10b로 DC(dc01) admin 거점을 얻으면 R8이 도메인(dom-sevenkingdoms)을 장악해야 함
    assert Fact.controls("dom-sevenkingdoms") in inf.facts


def test_r3_identity_actions_and_group_inherit():
    """R3가 reset_credential, add_member 및 group: 대상 비-admin 상속을 처리하는지 검증."""
    doc = {
        "ir_version": "0.2",
        "groups": [{"id": "g-app", "kind": "security_group"}],
        "assets": [
            {"id": "ext", "type": "external"},
            {"id": "u-help", "type": "identity", "kind": "user"},
            {"id": "u-priv", "type": "identity", "kind": "user"},
            {"id": "grp-adm", "type": "identity", "kind": "group"},
            {"id": "srv", "type": "host", "role": "app_server", "groups": ["g-app"]},
        ],
        "relations": [
            {"type": "has_permission", "from": "ext", "to": "u-help", "action": "delegate", "effect": "allow"},
            {"type": "has_permission", "from": "u-help", "to": "u-priv", "action": "reset_credential", "effect": "allow"},
            {"type": "has_permission", "from": "u-priv", "to": "grp-adm", "action": "add_member", "effect": "allow"},
            {"type": "has_permission", "from": "grp-adm", "to": "group:g-app", "action": "execute", "effect": "allow"},
        ],
    }
    res = run_variant(InfraGraph(doc), {"id": "ext", "start": ["ext"]}, "informed", "assumed_open")
    assert Fact.acts_as("u-help") in res.facts
    assert Fact.acts_as("u-priv") in res.facts
    assert Fact.acts_as("grp-adm") in res.facts
    assert Fact.foothold("srv", "user") in res.facts


def test_r10_managed_service_and_auth_probability_diff():
    """호스트 없는 managed_service 도달 및 인증 보호 서비스의 낮은 침해 확률 검증."""
    doc = {
        "ir_version": "0.2",
        "assets": [
            {"id": "ext", "type": "external"},
            {"id": "saas", "type": "service", "kind": "managed_service", "port": 443, "config": {"access.anonymous": True}},
            {"id": "db-host", "type": "host", "role": "db_server"},
            {
                "id": "svc-db",
                "type": "service",
                "kind": "network_service",
                "port": 5432,
                "config": {"auth.methods": ["password"], "auth.default_credentials": False, "auth.lockout": True},
            },
        ],
        "relations": [
            {"type": "reaches", "from": "ext", "to": "saas", "ports": [443]},
            {"type": "reaches", "from": "ext", "to": "db-host", "ports": [5432]},
            {"type": "runs", "from": "db-host", "to": "svc-db"},
        ],
    }
    res = run_variant(InfraGraph(doc), {"id": "ext", "start": ["ext"]}, "informed", "assumed_open")
    assert Fact.foothold("saas", "user") in res.facts
    assert Fact.foothold("db-host", "user") in res.facts
    p_saas = res.derivations[Fact.foothold("saas", "user")][0].prob
    p_db = res.derivations[Fact.foothold("db-host", "user")][0].prob
    assert p_db < p_saas
