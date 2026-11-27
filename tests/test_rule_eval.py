"""범용 DSL 규칙 평가기(WBS 3.1) 테스트.

기준선: 얇은 엔진(thin.py). core.yaml만 쓰면 사실 집합이 얇은 엔진과 정확히 같아야 하고,
확장 규칙(extended.yaml)을 더하면 얇은 엔진 사실 집합을 포함해야 한다.
확률은 규칙 파일의 사전분포·승수를 따르므로 얇은 엔진과 같을 필요는 없다.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scengen.engine import Fact, InfraGraph
from scengen.engine.rule_eval import analyze_doc_rules, load_ruleset, run_variant_rules
from scengen.engine.thin import analyze_doc
from scengen.ir import load_ir
from scengen.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "docs" / "samples"
SAMPLE_FILES = ["shop-hybrid.ir.yaml", "goad-infra.ir.yaml"]


@pytest.fixture(scope="module")
def core_rules():
    return load_ruleset(files=["core.yaml"])


@pytest.fixture(scope="module")
def all_rules():
    return load_ruleset()


@pytest.mark.parametrize("sample", SAMPLE_FILES)
def test_core_rules_match_thin_engine_facts(sample, core_rules):
    doc = load_ir(SAMPLES / sample)
    thin = analyze_doc(doc)
    dsl = analyze_doc_rules(doc, core_rules)
    assert len(thin) == len(dsl)
    for t, d in zip(thin, dsl):
        assert (t.profile_id, t.knowledge, t.egress) == (d.profile_id, d.knowledge, d.egress)
        assert t.facts == d.facts, (
            f"{t.profile_id}/{t.knowledge}/{t.egress}: "
            f"thin만 {sorted(map(str, t.facts - d.facts))}, DSL만 {sorted(map(str, d.facts - t.facts))}"
        )
        assert [g.achieved for g in t.goals] == [g.achieved for g in d.goals]


@pytest.mark.parametrize("sample", SAMPLE_FILES)
def test_extended_rules_are_superset_and_well_typed(sample, all_rules):
    doc = load_ir(SAMPLES / sample)
    graph = InfraGraph(doc)
    for t, d in zip(analyze_doc(doc), analyze_doc_rules(doc, all_rules)):
        assert t.facts <= d.facts
        for f in d.facts:
            if f.kind == "foothold":
                # 거점은 신원(identity)·데이터에 생기지 않는다
                assert graph.assets[f.args[0]].get("type") not in ("identity", "data"), f
        # 규칙이 만든 유도 단계의 확률은 (0, 1) 구간 (시작 상태 INIT·KNOWN_STATE는 제외)
        for steps in d.derivations.values():
            for s in steps:
                if s.rule_id not in ("INIT", "INIT_SESSION", "KNOWN_STATE"):
                    assert 0.0 < s.prob < 1.0, s


def test_uninformed_lowers_probability_and_records_knows_premise(core_rules):
    doc = load_ir(SAMPLES / "shop-hybrid.ir.yaml")
    res = {(v.profile_id, v.knowledge, v.egress): v for v in analyze_doc_rules(doc, core_rules)}
    inf = {g.goal_id: g for g in res[("external", "informed", "assumed_open")].goals}
    uninf_v = res[("external", "uninformed", "assumed_open")]
    uninf = {g.goal_id: g for g in uninf_v.goals}
    assert uninf["goal-customer-exfil"].prob < inf["goal-customer-exfil"].prob
    # uninformed에서 R10은 knows(host)를 전제로 기록해야 한다
    r10 = [s for steps in uninf_v.derivations.values() for s in steps if s.rule_id == "R10"]
    assert r10 and all(any(p.kind == "knows" for p in s.premises) for s in r10)


def test_chain_deny_and_encrypted_key(core_rules):
    doc = {
        "ir_version": "0.2",
        "assets": [
            {"id": "ext", "type": "external"},
            {"id": "st", "type": "data_store", "role": "backup"},
            {"id": "d1", "type": "data", "categories": ["personal"]},
            {"id": "d2", "type": "data", "categories": ["personal"]},
            {"id": "k1", "type": "credential", "kind": "key"},
            {"id": "st2", "type": "data_store", "role": "backup"},
        ],
        "relations": [
            {"type": "contains", "from": "st", "to": "d1", "encrypted": True, "key_ref": "k1"},
            {"type": "has_permission", "from": "ext", "to": "st", "action": "read", "effect": "allow"},
            {"type": "contains", "from": "st2", "to": "d2"},
            {"type": "has_permission", "from": "ext", "to": "st2", "action": "read", "effect": "allow"},
            {"type": "has_permission", "from": "ext", "to": "st2", "action": "read", "effect": "deny"},
        ],
    }
    res = run_variant_rules(InfraGraph(doc), {"id": "ext", "start": ["ext"]}, "informed", "assumed_open", core_rules)
    # 키가 없으면 암호화 데이터를 못 읽고, 거부 엣지가 허용보다 우선한다
    assert Fact.data_access("d1", "read") not in res.facts
    assert Fact.data_access("d2", "read") not in res.facts

    doc["context"] = {"known_state": [{"fact": {"has_credential": "k1"}, "probability": 1.0}]}
    res = run_variant_rules(InfraGraph(doc), {"id": "ext", "start": ["ext"]}, "informed", "assumed_open", core_rules)
    step = res.derivations[Fact.data_access("d1", "read")][0]
    assert step.rule_id == "R3-data-read-encrypted"
    assert Fact.has_credential("k1") in step.premises
    assert any(src.startswith("has_permission:ext->st") for src in step.source_relations)


def test_add_member_only_on_group_and_modifiers(core_rules):
    doc = {
        "ir_version": "0.2",
        "assets": [
            {"id": "ext", "type": "external"},
            {"id": "u-a", "type": "identity", "kind": "user"},
            {"id": "grp", "type": "identity", "kind": "group"},
            {"id": "saas", "type": "service", "kind": "managed_service", "port": 443, "config": {"access.anonymous": True}},
            {"id": "db-host", "type": "host", "role": "db_server"},
            {"id": "svc-db", "type": "service", "kind": "network_service", "port": 5432,
             "config": {"auth.methods": ["password"], "auth.default_credentials": False, "auth.lockout": True}},
        ],
        "relations": [
            {"type": "has_permission", "from": "ext", "to": "u-a", "action": "add_member", "effect": "allow"},
            {"type": "has_permission", "from": "ext", "to": "grp", "action": "add_member", "effect": "allow"},
            {"type": "reaches", "from": "ext", "to": "saas", "ports": [443]},
            {"type": "reaches", "from": "ext", "to": "db-host", "ports": [5432]},
            {"type": "runs", "from": "db-host", "to": "svc-db"},
        ],
    }
    res = run_variant_rules(InfraGraph(doc), {"id": "ext", "start": ["ext"]}, "informed", "assumed_open", core_rules)
    assert Fact.acts_as("grp") in res.facts
    assert Fact.acts_as("u-a") not in res.facts  # add_member는 그룹에만 의미가 있다
    # 호스트에서 실행되는 서비스는 R10-managed가 아니라 R10이 다룬다
    assert Fact.foothold("svc-db", "user") not in res.facts
    p_saas = res.derivations[Fact.foothold("saas", "user")][0].prob
    p_db = res.derivations[Fact.foothold("db-host", "user")][0].prob
    assert p_db < p_saas


def test_loader_rejects_unknown_when_clause(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        """
rule_version: "0.1"
rules:
  - id: R-BAD
    name: "모르는 절"
    category: transition
    vars:
      a: { type: asset }
    when:
      - relation: { type: runs, from: $a }
      - reachez: { from: $a }
    requires:
      - foothold($a, user)
    adds:
      - foothold($a, admin)
    probability:
      base: { kind: beta, alpha: 1, beta: 1 }
""",
        encoding="utf-8",
    )
    res = load_rules(tmp_path)
    assert any("알 수 없는 when 절 'reachez'" in e for e in res.errors)


def test_reproducible_across_hash_seeds():
    """사실·유도 단계 순서가 PYTHONHASHSEED에 따라 달라지지 않는다 (재현성)."""
    script = (
        "from scengen.ir import load_ir\n"
        "from scengen.engine.rule_eval import analyze_doc_rules\n"
        f"for v in analyze_doc_rules(load_ir({str(SAMPLES / 'goad-infra.ir.yaml')!r})):\n"
        "    for f, steps in sorted(v.derivations.items(), key=lambda kv: str(kv[0])):\n"
        "        print(f, [(s.rule_id, tuple(map(str, s.premises)), s.prob) for s in steps])\n"
    )
    outs = []
    for seed in ("1", "2"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        outs.append(subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, check=True).stdout)
    assert outs[0] == outs[1] and outs[0]
