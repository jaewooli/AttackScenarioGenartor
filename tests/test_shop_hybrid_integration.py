"""Runs only when added to the real repository with the shop-hybrid fixture."""
from pathlib import Path
import pytest
from scengen.thin_engine import ThinEngine


def test_shop_hybrid_smoke():
    sample = Path(__file__).resolve().parents[1] / 'docs/samples/shop-hybrid.ir.yaml'
    if not sample.exists():
        pytest.skip('원본 shop-hybrid 샘플 미확보: 저장소에 패치 적용 후 실행')
    yaml = pytest.importorskip('yaml')
    ir = yaml.safe_load(sample.read_text(encoding='utf-8'))
    assert isinstance(ir, dict)
    assert 'assets' in ir and 'relations' in ir
    profiles = ir.get('attacker_profiles') or []
    assert profiles, 'shop-hybrid attacker_profiles 없음'
    for profile in profiles:
        e = ThinEngine(ir)
        e.seed_profile(profile)
        report = e.run()
        assert report['rounds'] >= 1
        assert report['facts']
        assert report == repeat(ir, profile)


def repeat(ir, profile):
    e = ThinEngine(ir)
    e.seed_profile(profile)
    return e.run()
