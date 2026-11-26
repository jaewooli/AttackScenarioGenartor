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
