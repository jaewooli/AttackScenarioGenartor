"""목표 자동 생성기(WBS 3.2) 단위 테스트."""

from pathlib import Path

from scengen.engine import InfraGraph
from scengen.engine.goals import generate_auto_goals
from scengen.ir import load_ir

SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "samples"


def test_auto_goals_on_shop_hybrid_without_explicit_goals():
    doc = load_ir(SAMPLES / "shop-hybrid.ir.yaml")
    doc.pop("impact_goals", None)
    goals = generate_auto_goals(InfraGraph(doc))
    by_id = {g["id"]: g for g in goals}

    # data-customer, data-payment에 대해 exfil + tamper 생성
    assert "auto-exfil-data-customer" in by_id
    assert "auto-tamper-data-customer" in by_id
    assert "auto-exfil-data-payment" in by_id
    # public 데이터는 exfil 제외, tamper만 생성
    assert "auto-exfil-data-product-images" not in by_id
    assert "auto-tamper-data-product-images" in by_id
    # customer_id 겹침 결합 목표 생성 + 등급 상향(critical)
    comb = by_id["auto-combined-data-customer-data-payment"]
    assert comb["impact"]["level"] == "critical"
    # business_service disrupt + downtime_impact.per_hour(high) 반영
    assert by_id["auto-disrupt-biz-shop"]["impact"]["level"] == "high"


def test_auto_domain_takeover_goals_on_goad():
    """데이터·업무 서비스가 없는 GOAD에서도 도메인 장악 목표가 생기고, 내부자 변형에서 달성된다."""
    from scengen.engine import analyze_doc_rules

    doc = load_ir(SAMPLES / "goad-infra.ir.yaml")
    goals = {g["id"]: g for g in generate_auto_goals(InfraGraph(doc))}
    assert set(goals) == {"auto-takeover-dom-sevenkingdoms", "auto-takeover-dom-north", "auto-takeover-dom-essos"}
    g = goals["auto-takeover-dom-sevenkingdoms"]
    assert g["harm"] == "misuse"
    assert g["condition"] == {"controls": "group:dom-sevenkingdoms"}
    assert g["impact"] == {"level": "critical", "source": "assumed"}

    inf = next(v for v in analyze_doc_rules(doc) if v.knowledge == "informed" and v.egress == "assumed_open")
    outcome = {o.goal_id: o for o in inf.goals}
    assert outcome["auto-takeover-dom-sevenkingdoms"].achieved
    assert outcome["auto-takeover-dom-sevenkingdoms"].prob > 0
