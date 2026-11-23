from pathlib import Path

import yaml


def test_initial_rules_match_dsl_and_shop_relations():
    root = Path(__file__).resolve().parents[1]
    sample = yaml.safe_load((root / "docs/samples/shop-hybrid.ir.yaml").read_text())
    paths = sorted((root / "rules").glob("*.yaml"))
    assert {p.stem for p in paths} == {
        "network-reach", "permission-scope", "stored-data-read", "discovery-uninformed"
    }
    for path in paths:
        rule = yaml.safe_load(path.read_text())
        assert set(rule) == {"id", "version", "when", "then", "prior", "attack_ids"}
        assert rule["id"] == path.stem and rule["version"] == 1
        bound = set()
        for pattern in rule["when"]["all"]:
            if "fact" in pattern:
                fact = pattern["fact"]
                assert len(fact["args"]) == {"knows": 1, "foothold": 2}[fact["kind"]]
                bound.update(fact["args"])
            else:
                relation = pattern["relation"]
                assert any(all(k in row and (v.startswith("$") or row[k] == v)
                               for k, v in relation.items()) for row in sample["relations"])
                bound.update(v for v in relation.values() if v.startswith("$"))
        assert rule["then"]["subject"] in bound
        assert rule["then"]["kind"] == "candidate" and rule["then"]["question"]
        assert rule["prior"] is None
