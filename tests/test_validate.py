import copy
from pathlib import Path

import pytest

from scengen.cli import main
from scengen.ir import validate_file, validate_ir

ROOT = Path(__file__).resolve().parents[1]
GOAD = ROOT / "docs" / "samples" / "goad-infra.ir.yaml"

BASE = {
    "ir_version": "0.2",
    "meta": {"name": "t", "sources": [{"id": "src1", "kind": "manual"}]},
    "groups": [
        {"id": "vpc", "kind": "vpc"},
        {"id": "sub", "kind": "subnet", "parent": "vpc"},
    ],
    "assets": [
        {"id": "h1", "type": "host", "role": "web_server", "groups": ["sub"]},
        {"id": "s1", "type": "service", "product": "nginx", "port": 443},
        {"id": "u1", "type": "identity", "kind": "user"},
        {"id": "g1", "type": "identity", "kind": "group"},
        {"id": "d1", "type": "data", "categories": ["personal"]},
        {"id": "db", "type": "data_store"},
    ],
    "relations": [
        {"type": "runs", "from": "h1", "to": "s1"},
        {"type": "member_of", "from": "u1", "to": "g1"},
        {"type": "contains", "from": "db", "to": "d1"},
        {"type": "reaches", "from": "group:sub", "to": "group:sub"},
    ],
}


def doc(**changes):
    d = copy.deepcopy(BASE)
    for k, v in changes.items():
        d[k] = v
    return d


def messages(result, level="error"):
    return [i.message for i in result.issues if i.level == level]


# ------------------------------------------------------------ 정상 입력

def test_goad_sample_is_valid():
    result = validate_file(GOAD)
    assert result.ok, [str(i) for i in result.issues]
    assert not result.warnings


def test_base_doc_is_valid():
    result = validate_ir(doc())
    assert result.ok, [str(i) for i in result.issues]


def test_attr_object_forms_accepted():
    d = doc()
    d["assets"][1]["version"] = {"value": None, "source": "unknown"}
    d["assets"][4]["categories"] = {"value": ["personal"], "source": "inferred", "confidence": 0.8}
    assert validate_ir(d).ok


# ------------------------------------------------------------ 구조 오류

@pytest.mark.parametrize("mutate, expect", [
    (lambda d: d.update(ir_version="0.1"), "0.2"),
    (lambda d: d["assets"][0].update(type="server"), "is not one of"),
    (lambda d: d["assets"][0].update(colour="red"), "Unevaluated properties"),
    (lambda d: d["assets"][2].pop("kind"), "'kind' is a required property"),
    (lambda d: d["relations"].append({"type": "has_permission", "from": "u1", "to": "h1"}),
     "'action' is a required property"),
    (lambda d: d["assets"][4].update(categories=["secret_stuff"]), "categories"),
    (lambda d: d["assets"][1].update(port=70000), "70000"),
    (lambda d: d["assets"][1].update(version={"confidence": 0.5}), "version"),
])
def test_schema_errors(mutate, expect):
    d = doc()
    mutate(d)
    result = validate_ir(d)
    assert not result.ok
    joined = " | ".join(f"{i.path} {i.message}" for i in result.errors)
    assert expect in joined


def test_semantic_check_skipped_when_schema_fails():
    d = doc(ir_version="9")
    d["relations"].append({"type": "runs", "from": "h1", "to": "nope"})
    result = validate_ir(d)
    assert any("의미 검증을 건너뜀" in m for m in messages(result, "warning"))
    assert not any("nope" in m for m in messages(result))


# ------------------------------------------------------------ 의미 오류

def test_missing_reference():
    d = doc()
    d["relations"].append({"type": "runs", "from": "h1", "to": "ghost"})
    assert any("존재하지 않는 참조 'ghost'" in m for m in messages(validate_ir(d)))


def test_group_needs_prefix():
    d = doc()
    d["relations"].append({"type": "reaches", "from": "h1", "to": "sub"})
    assert any("group:sub" in m for m in messages(validate_ir(d)))


def test_duplicate_id():
    d = doc()
    d["assets"].append({"id": "h1", "type": "host"})
    assert any("중복 id 'h1'" in m for m in messages(validate_ir(d)))


def test_id_shared_between_group_and_asset():
    d = doc()
    d["assets"].append({"id": "vpc", "type": "host"})
    assert any("그룹과 자산에 동시에" in m for m in messages(validate_ir(d)))


def test_group_cycle():
    d = doc()
    d["groups"][0]["parent"] = "sub"
    assert any("순환" in m for m in messages(validate_ir(d)))


def test_missing_parent_group():
    d = doc()
    d["groups"][1]["parent"] = "nowhere"
    assert any("상위 그룹 'nowhere'" in m for m in messages(validate_ir(d)))


def test_asset_in_unknown_group():
    d = doc()
    d["assets"][0]["groups"] = ["sub", "dmz"]
    assert any("존재하지 않는 그룹 'dmz'" in m for m in messages(validate_ir(d)))


@pytest.mark.parametrize("rel, side", [
    ({"type": "runs", "from": "s1", "to": "h1"}, "출발"),           # 서비스가 호스트를 실행
    ({"type": "contains", "from": "db", "to": "h1"}, "도착"),        # 저장소가 호스트를 담음
    ({"type": "member_of", "from": "u1", "to": "u1"}, "자기 자신"),  # 자기 소속
    ({"type": "member_of", "from": "g1", "to": "u1"}, "도착"),       # 사용자에 소속
])
def test_relation_type_rules(rel, side):
    d = doc()
    d["relations"].append(rel)
    assert any(side in m for m in messages(validate_ir(d)))


def test_unknown_with_value_is_error():
    d = doc()
    d["assets"][1]["version"] = {"value": "1.0", "source": "unknown"}
    assert any("unknown인데 value" in m for m in messages(validate_ir(d)))


def test_attr_warnings():
    d = doc()
    d["assets"][1]["version"] = {"value": "1.0", "source": "declared", "confidence": 0.5}
    d["assets"][1]["product"] = {"value": "nginx", "source": "inferred"}
    d["assets"][0]["evidence"] = "nosuchsrc"
    result = validate_ir(d)
    assert result.ok
    warns = messages(result, "warning")
    assert any("declared인데" in m for m in warns)
    assert any("confidence가 없음" in m for m in warns)
    assert any("nosuchsrc" in m for m in warns)


def test_goal_and_profile_references():
    d = doc()
    d["impact_goals"] = [{
        "id": "g-x", "harm": "exfiltrate",
        "condition": {"all": [{"exfiltrated": "d1"}, {"has_credential": "missing-key"},
                              {"acts_as": "ghost-user"}]},
    }]
    d["attacker_profiles"] = [{"id": "ext", "start": ["nobody"]}]
    d["context"] = {"known_state": [{"fact": {"exfiltrated": "ghost-data"}, "probability": 1.0}]}
    errs = messages(validate_ir(d))
    assert any("missing-key" in m for m in errs)
    assert any("ghost-user" in m for m in errs)
    assert any("nobody" in m for m in errs)
    assert any("ghost-data" in m for m in errs)


def test_profile_variants():
    from scengen.ir.validate import profile_variants

    assert len(profile_variants({"id": "p", "start": ["h1"]})) == 4
    assert profile_variants({"id": "p", "start": ["h1"], "knowledge": "informed", "egress": "from_ir"}) == [
        {"knowledge": "informed", "egress": "from_ir"}]
    assert len(profile_variants({"id": "p", "start": ["h1"], "knowledge": ["informed"]})) == 2


@pytest.mark.parametrize("profile, ok", [
    ({"id": "p", "start": ["h1"], "knowledge": ["informed", "uninformed"], "egress": "from_ir"}, True),
    ({"id": "p", "start": ["h1"], "knowledge": "clueless"}, False),
    ({"id": "p", "start": ["h1"], "egress": []}, False),
    ({"id": "p", "start": ["h1"], "initial_privilege": "god"}, False),
])
def test_profile_assumption_fields(profile, ok):
    d = doc()
    d["attacker_profiles"] = [profile]
    assert validate_ir(d).ok is ok


def test_condition_leaf_shape():
    d = doc()
    d["impact_goals"] = [{"id": "g", "harm": "tamper", "condition": {"exfiltrated": "d1", "read": "d1"}}]
    assert not validate_ir(d).ok


# ------------------------------------------------------------ 관계 타입별 필드 (항목 6)

@pytest.mark.parametrize("rel", [
    {"type": "member_of", "from": "u1", "to": "g1", "ports": [80]},
    {"type": "runs", "from": "h1", "to": "s1", "action": "read"},
    {"type": "contains", "from": "db", "to": "d1", "direction": "one_way"},
    {"type": "reaches", "from": "h1", "to": "s1", "kind": "x"},
])
def test_field_not_allowed_for_relation_type(rel):
    d = doc()
    d["relations"].append(rel)
    result = validate_ir(d)
    assert any("Unevaluated properties" in m for m in messages(result))


def test_fields_allowed_for_their_type():
    d = doc()
    d["relations"] += [
        {"type": "reaches", "from": "group:sub", "to": "s1", "ports": [443], "protocol": "tcp"},
        {"type": "has_permission", "from": "g1", "to": "db", "action": "read", "effect": "allow", "inherit": True},
        {"type": "contains", "from": "db", "to": "d1", "encrypted": True},
        {"type": "trusts", "from": "group:vpc", "to": "group:sub", "kind": "x", "direction": "one_way"},
    ]
    assert validate_ir(d).ok, [str(i) for i in validate_ir(d).issues]


# ------------------------------------------------------------ 실행 계정, 세션 (항목 2)

def test_runs_as_and_session():
    d = doc()
    d["assets"].append({"id": "svc-acct", "type": "identity", "kind": "service_account"})
    d["relations"][0].update({"as": "svc-acct", "privilege": "user"})
    d["relations"].append({"type": "session", "from": "u1", "to": "h1",
                           "logon": "remote_interactive", "frequency": "periodic"})
    assert validate_ir(d).ok, [str(i) for i in validate_ir(d).issues]


def test_runs_as_must_be_identity():
    d = doc()
    d["relations"][0]["as"] = "h1"
    assert any("identity" in m for m in messages(validate_ir(d)))


def test_session_endpoints():
    d = doc()
    d["relations"].append({"type": "session", "from": "u1", "to": "s1"})   # 웹·SaaS 서비스 세션은 허용
    assert validate_ir(d).ok
    d["relations"].append({"type": "session", "from": "u1", "to": "db"})   # 저장소에는 세션 없음
    assert any("도착" in m for m in messages(validate_ir(d)))


# ------------------------------------------------------------ 설정 키 사전

def test_config_keys():
    d = doc()
    d["groups"][1]["config"] = {"host.firewall": "enabled"}
    d["assets"][1]["config"] = {
        "auth.methods": ["password", "kerberos"],
        "transport.signing": {"value": None, "source": "assumed",
                              "distribution": {"kind": "categorical",
                                               "p": {"none": 0.3, "optional": 0.5, "required": 0.2}}},
    }
    assert validate_ir(d).ok, [str(i) for i in validate_ir(d).issues]


@pytest.mark.parametrize("config, level, expect", [
    ({"host.firewall": "maybe"}, "error", "허용값"),
    ({"auth.mfa": "yes"}, "error", "true/false"),
    ({"auth.methods": ["password", "telepathy"]}, "error", "telepathy"),
    ({"auth.methods": {"value": "password", "source": "declared"}}, "error", "목록"),
    ({"custom.thing": True}, "warning", "사전에 없는 키"),
])
def test_config_key_problems(config, level, expect):
    d = doc()
    d["assets"][0]["config"] = config
    assert any(expect in m for m in messages(validate_ir(d), level))


def test_config_key_format():
    d = doc()
    d["assets"][0]["config"] = {"Firewall": "enabled"}
    assert not validate_ir(d).ok


# ------------------------------------------------------------ 분포 (항목 4)

def test_distribution_checks():
    d = doc()
    d["assets"][1]["version"] = {"source": "assumed",
                                 "distribution": {"kind": "categorical", "p": {"1.18": 0.5, "1.20": 0.2}}}
    assert any("합이 1이 아님" in m for m in messages(validate_ir(d)))

    d = doc()
    d["assets"][1]["version"] = {"value": "1.0", "source": "declared",
                                 "distribution": {"kind": "bernoulli", "p": 0.4}}
    assert any("declared인데 distribution" in m for m in messages(validate_ir(d), "warning"))

    d = doc()
    d["assets"][1]["version"] = {"source": "assumed", "distribution": {"kind": "beta", "a": 0, "b": 1}}
    assert not validate_ir(d).ok


def test_assumed_without_confidence_or_distribution_warns():
    d = doc()
    d["assets"][1]["version"] = {"value": "1.0", "source": "assumed"}
    assert any("기본 사전분포" in m for m in messages(validate_ir(d), "warning"))


# ------------------------------------------------------------ CLI

def test_cli_exit_codes(tmp_path, capsys):
    assert main(["validate", str(GOAD)]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("ir_version: '0.2'\nassets:\n  - {id: a, type: nope}\n", encoding="utf-8")
    assert main(["validate", str(bad)]) == 1
    broken = tmp_path / "broken.yaml"
    broken.write_text("ir_version: [\n", encoding="utf-8")
    assert main(["validate", str(broken)]) == 1
    assert main(["validate", str(tmp_path / "missing.yaml")]) == 2
    out = capsys.readouterr().out
    assert "OK" in out and "FAIL" in out
