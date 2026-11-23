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


def test_shop_hybrid_assessment_evidence():
    import yaml

    sample = Path(__file__).resolve().parents[1] / 'docs/samples/shop-hybrid.ir.yaml'
    ir = yaml.safe_load(sample.read_text(encoding='utf-8'))
    engine = ThinEngine(ir)
    profile = next(p for p in ir['attacker_profiles'] if 'ext-internet' in p['start'])
    engine.seed_profile(profile)
    records = engine.run()['assessments']

    def evidence(kind, source, target):
        relation = next(r for r in ir['relations'] if
                        (r['type'], r['from'], r['to']) == (kind, source, target))
        return engine.rel_id(relation)

    assert any(r['status'] == 'confirmed' and r['evidence'] ==
               [evidence('hosts', 'db-01', 'store-db')] for r in records)
    assert any(r['status'] == 'candidate' and r['subject'] == 'svc-web'
               and 'lb-01' in r['question'] and r['evidence'] ==
               [evidence('reaches', 'ext-internet', 'group:nsg-web'),
                evidence('runs', 'web-01', 'svc-web')] for r in records)
    assert any(r['status'] == 'unevaluated' and '데이터' in r['reason']
               and r['evidence'] == [evidence('has_permission', 'role-backup', 'store-backup')]
               for r in records)
