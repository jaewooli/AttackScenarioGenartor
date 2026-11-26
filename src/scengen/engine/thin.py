"""얇은 엔진 MVP: 최소 규칙 R1~R11(+ LPE R10b, 발견 D1~D4)을 Python으로 직접 구현.

목적:
- docs/ir-field-audit.md의 R1~R11과 docs/attacker-state.md의 상태 모델·분석 변형을
  실제 IR 샘플(shop-hybrid, goad-infra)에서 돌려보며 규칙 형식(WBS 2.2)의 요구사항을 검증한다.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..ir.validate import profile_variants
from .goals import generate_auto_goals
from .graph import InfraGraph, is_group_ref, strip_group_prefix
from .model import (
    PRIVILEGE_ORDER,
    DerivationStep,
    Fact,
    GoalOutcome,
    VariantResult,
    obj_confidence,
    priv_at_least,
    unwrap_attr,
)

CAPABILITY_FACTOR: dict[str, float] = {
    "low": 0.45,
    "medium": 0.70,
    "high": 0.88,
    "advanced": 0.96,
}

FREQUENCY_PROB: dict[str, float] = {
    "persistent": 0.95,
    "periodic": 0.65,
    "occasional": 0.30,
    "unknown": 0.40,
}


def _best_footholds(facts: set[Fact]) -> dict[str, str]:
    """자산별 현재 최고 foothold 권한 수준을 반환한다."""
    best: dict[str, str] = {}
    for f in facts:
        if f.kind != "foothold":
            continue
        asset, lvl = f.args
        if asset not in best or PRIVILEGE_ORDER[lvl] > PRIVILEGE_ORDER[best[asset]]:
            best[asset] = lvl
    return best


def _foothold_fact_for(facts: set[Fact], asset: str, min_level: str) -> Fact | None:
    """min_level 이상인 foothold 사실 중 가장 높은 것을 반환한다."""
    best_lvl: str | None = None
    for f in facts:
        if f.kind == "foothold" and f.args[0] == asset and priv_at_least(f.args[1], min_level):
            if best_lvl is None or PRIVILEGE_ORDER[f.args[1]] > PRIVILEGE_ORDER[best_lvl]:
                best_lvl = f.args[1]
    return Fact.foothold(asset, best_lvl) if best_lvl else None


def _know_prem(facts: set[Fact], knowledge: str, target: str) -> tuple[Fact, ...] | None:
    """uninformed 변형이면 knows(target) 전제 튜플을, informed면 빈 튜플을 반환. 모르면 None."""
    if knowledge == "informed":
        return ()
    kf = Fact.knows(target)
    return (kf,) if kf in facts else None


def _exploit_prob(graph: InfraGraph, host_id: str | None, svc_id: str | None, capability: str) -> float:
    """R10 노출 서비스 침해의 단순 사전 확률 추정."""
    cap = CAPABILITY_FACTOR.get(capability, 0.70)
    base = 0.35
    if svc_id:
        anon, _, _ = graph.get_config(svc_id, "access.anonymous")
        auth_methods, _, _ = graph.get_config(svc_id, "auth.methods")
        default_cred, _, _ = graph.get_config(svc_id, "auth.default_credentials")
        lockout, _, _ = graph.get_config(svc_id, "auth.lockout")
        # 인증이 필수이고 기본 자격증명·잠금 통제가 있으면 노출 침해 확률을 낮춤
        if auth_methods and anon is not True:
            base = 0.14
            if default_cred is False:
                base *= 0.75
            if lockout is True:
                base *= 0.80

        sec_dev, _, _ = graph.get_config(svc_id, "app.secure_development")
        waf, _, _ = graph.get_config(svc_id, "network.application_filtering")
        if sec_dev is True:
            base *= 0.55
        if waf is True:
            base *= 0.70
    if host_id:
        patch, _, _ = graph.get_config(host_id, "host.patch_currency")
        if patch == "lagging":
            base = min(0.85, base * 1.8)
        elif patch == "current":
            base *= 0.75
    return round(min(0.95, max(0.03, base * cap)), 4)


def _lpe_prob(graph: InfraGraph, host_id: str, capability: str) -> float:
    """R10b 로컬 권한 상승의 단순 사전 확률 추정."""
    cap = CAPABILITY_FACTOR.get(capability, 0.70)
    base = 0.30
    patch, _, _ = graph.get_config(host_id, "host.patch_currency")
    hardening, _, _ = graph.get_config(host_id, "host.os_hardening")
    epp, _, _ = graph.get_config(host_id, "host.endpoint_protection")
    if patch == "lagging":
        base = 0.65
    elif patch == "current":
        base *= 0.65
    if hardening == "strict":
        base *= 0.60
    elif hardening == "baseline":
        base *= 0.80
    if epp is True:
        base *= 0.75
    return round(min(0.90, max(0.04, base * cap)), 4)


def _initial_facts(graph: InfraGraph, profile: dict[str, Any], knowledge: str) -> tuple[set[Fact], dict[Fact, list[DerivationStep]]]:
    facts: set[Fact] = set()
    derivs: dict[Fact, list[DerivationStep]] = defaultdict(list)

    init_priv = profile.get("initial_privilege", "none")
    for start_id in profile.get("start") or []:
        asset = graph.assets.get(start_id)
        if not asset:
            continue
        lvl = "none" if asset.get("type") == "external" else init_priv
        f = Fact.foothold(start_id, lvl)
        facts.add(f)
        derivs[f].append(DerivationStep("INIT", f, (), 1.0, f"시작점 {start_id} ({lvl})"))
        if knowledge == "uninformed":
            kf = Fact.knows(start_id)
            facts.add(kf)
            derivs[kf].append(DerivationStep("INIT", kf, (), 1.0, "시작점 인지"))

        # 내부자 시작 단말의 session에 연결된 주체가 있으면 acts_as 추가 (attacker-state.md 4장)
        if lvl != "none":
            for r in graph.by_type.get("session", []):
                if r["to"] == start_id:
                    ident = graph.assets.get(r["from"])
                    if ident and ident.get("type") == "identity" and ident.get("kind") != "group":
                        af = Fact.acts_as(r["from"])
                        facts.add(af)
                        derivs[af].append(
                            DerivationStep("INIT_SESSION", af, (f,), obj_confidence(r), f"{start_id} 초기 세션")
                        )

    # context.known_state 반영
    for item in graph.context.get("known_state") or []:
        prob = float(item.get("probability", 1.0))
        fact_dict = item.get("fact") or {}
        for k, v in fact_dict.items():
            f: Fact | None = None
            if k == "exfiltrated":
                f = Fact.data_access(str(v), "read")
            elif k == "acts_as":
                f = Fact.acts_as(str(v))
            elif k == "has_credential":
                f = Fact.has_credential(str(v))
            elif k == "controls":
                f = Fact.controls(strip_group_prefix(str(v)))
            if f:
                facts.add(f)
                derivs[f].append(DerivationStep("KNOWN_STATE", f, (), prob, item.get("evidence", "known_state")))

    return facts, derivs


def _is_denied(graph: InfraGraph, actor_id: str, target_id: str, action: str) -> bool:
    for r in graph.by_type.get("has_permission", []):
        if r.get("effect") != "deny":
            continue
        if r["from"] != actor_id:
            continue
        if not graph.matches_target(target_id, r["to"]):
            continue
        act = r.get("action")
        if act in (action, "admin"):
            return True
    return False


def run_variant(
    graph: InfraGraph,
    profile: dict[str, Any],
    knowledge: str,
    egress: str,
) -> VariantResult:
    """단일 (profile, knowledge, egress) 변형에 대해 R1~R11을 고정점까지 실행한다."""
    capability = profile.get("capability", "medium")
    facts, derivs = _initial_facts(graph, profile, knowledge)
    seen_steps: set[tuple[str, Fact, tuple[Fact, ...]]] = set()

    def add_step(rule_id: str, conclusion: Fact, premises: tuple[Fact, ...], prob: float, note: str = "") -> bool:
        key = (rule_id, conclusion, premises)
        if key in seen_steps:
            return False
        seen_steps.add(key)
        derivs[conclusion].append(DerivationStep(rule_id, conclusion, premises, prob, note))
        if conclusion not in facts:
            facts.add(conclusion)
            return True
        return False

    # runs 역인덱스: service -> list of (host, run_rel)
    svc_hosts: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for r in graph.by_type.get("runs", []):
        svc_hosts[r["to"]].append((r["from"], r))

    # hosts 역인덱스: child -> list of (host, host_rel)
    hosted_by: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for r in graph.by_type.get("hosts", []):
        hosted_by[r["to"]].append((r["from"], r))

    changed = True
    while changed:
        changed = False
        best_fh = _best_footholds(facts)

        # ---- 발견 규칙 (uninformed 변형 전용) ----
        if knowledge == "uninformed":
            for src_id, lvl in list(best_fh.items()):
                src_fact = Fact.foothold(src_id, lvl)
                # D2: 네트워크 도달 가능한 대상 발견
                for dst_id in graph.assets:
                    if graph.can_reach(src_id, dst_id):
                        if add_step("D2", Fact.knows(dst_id), (src_fact,), 0.85, f"{src_id}에서 정찰"):
                            changed = True
                # D3: 거점에서 실행 서비스·보관 자격증명·호스팅 저장소 발견
                if priv_at_least(lvl, "user"):
                    for r in graph.by_type.get("runs", []):
                        if r["from"] == src_id:
                            if add_step("D3", Fact.knows(r["to"]), (src_fact,), 0.95, "실행 서비스 식별"):
                                changed = True
                    for r in graph.by_type.get("stores", []):
                        if r["from"] == src_id:
                            if add_step("D3", Fact.knows(r["to"]), (src_fact,), 0.80, "보관 자격증명 발견"):
                                changed = True
                    for r in graph.by_type.get("hosts", []):
                        if r["from"] == src_id:
                            if add_step("D3", Fact.knows(r["to"]), (src_fact,), 0.95, "호스팅 대상 발견"):
                                changed = True

            for f in list(facts):
                if f.kind == "acts_as":
                    uid = f.args[0]
                    for r in graph.by_type.get("authenticates_to", []) + graph.by_type.get("has_permission", []):
                        if r["from"] == uid:
                            for tid in graph.expand_ref_assets(r["to"]):
                                if add_step("D4", Fact.knows(tid), (f,), 0.90, f"{uid} 권한 대상 조회"):
                                    changed = True

        # ---- R1: 그룹 소속 ----
        for f in list(facts):
            if f.kind != "acts_as":
                continue
            uid = f.args[0]
            for r in graph.by_type.get("member_of", []):
                if r["from"] == uid:
                    tgt = graph.assets.get(r["to"])
                    if tgt and tgt.get("type") == "identity" and tgt.get("kind") == "group":
                        if add_step("R1", Fact.acts_as(r["to"]), (f,), obj_confidence(r), f"{uid} ∈ {r['to']}"):
                            changed = True

        # ---- R2: 정상 로그인 (acts_as + authenticates_to + 도달 가능) ----
        for f in list(facts):
            if f.kind != "acts_as":
                continue
            uid = f.args[0]
            for r in graph.by_type.get("authenticates_to", []):
                if r["from"] != uid:
                    continue
                target_id = r["to"]
                kp = _know_prem(facts, knowledge, target_id)
                if kp is None:
                    continue
                priv, priv_conf, _ = unwrap_attr(r.get("privilege"), "user")
                if not isinstance(priv, str):
                    priv = "user"
                # target이 서비스면 실행 호스트의 포트/프로토콜로도 도달 검사
                target_asset = graph.assets.get(target_id, {})
                target_port = target_asset.get("port")
                target_proto = target_asset.get("protocol")
                reach_hosts = [target_id] + [h for h, _ in svc_hosts.get(target_id, [])]
                for src_id, lvl in list(best_fh.items()):
                    src_fact = Fact.foothold(src_id, lvl)
                    for rh in reach_hosts:
                        matches = graph.can_reach(
                            src_id,
                            rh,
                            port=target_port if rh != target_id else None,
                            protocol=target_proto if rh != target_id else None,
                        )
                        if matches:
                            p = round(obj_confidence(r) * priv_conf * max(m.confidence for m in matches), 4)
                            if add_step("R2", Fact.foothold(target_id, priv), (f, src_fact) + kp, p, f"{uid} → {target_id}"):
                                changed = True
                            # 서비스 로그인 시 호스트 거점도 동일 권한으로 부여(해당 서비스 호스트)
                            for h_id, run_rel in svc_hosts.get(target_id, []):
                                if add_step("R2", Fact.foothold(h_id, priv), (f, src_fact) + kp, round(p * obj_confidence(run_rel), 4), f"{uid} → {target_id} on {h_id}"):
                                    changed = True

        # ---- R3: 권한 사용 (acts_as 또는 external foothold + has_permission) ----
        actor_facts: list[tuple[str, Fact]] = [(f.args[0], f) for f in facts if f.kind == "acts_as"]
        for aid, lvl in best_fh.items():
            a = graph.assets.get(aid)
            if a and a.get("type") == "external":
                actor_facts.append((aid, Fact.foothold(aid, lvl)))

        for actor_id, actor_fact in actor_facts:
            for r in graph.by_type.get("has_permission", []):
                if r["from"] != actor_id or r.get("effect", "allow") != "allow":
                    continue
                action = r.get("action", "read")
                if _is_denied(graph, actor_id, r["to"], action):
                    continue
                cond_prob = 0.7 if r.get("condition") else 1.0
                base_p = round(obj_confidence(r) * cond_prob, 4)

                if is_group_ref(r["to"]):
                    gid = strip_group_prefix(r["to"])
                    if action in ("admin", "modify_permissions", "take_ownership"):
                        if add_step("R3", Fact.controls(gid), (actor_fact,), base_p, f"{actor_id} {action} on group:{gid}"):
                            changed = True
                    if r.get("inherit") is False:
                        continue

                for tid in graph.expand_ref_assets(r["to"]):
                    kp = _know_prem(facts, knowledge, tid)
                    if kp is None:
                        continue
                    t_asset = graph.assets.get(tid)
                    if not t_asset:
                        continue
                    ttype = t_asset.get("type")
                    if ttype == "data_store":
                        for cr in graph.by_type.get("contains", []):
                            if cr["from"] != tid:
                                continue
                            did = cr["to"]
                            if action in ("read", "admin", "modify_permissions", "take_ownership"):
                                if cr.get("encrypted") and cr.get("key_ref"):
                                    kf = Fact.has_credential(cr["key_ref"])
                                    if kf in facts:
                                        if add_step("R3", Fact.data_access(did, "read"), (actor_fact, kf) + kp, round(base_p * obj_confidence(cr), 4), f"{tid} 복호화 읽기"):
                                            changed = True
                                else:
                                    if add_step("R3", Fact.data_access(did, "read"), (actor_fact,) + kp, round(base_p * obj_confidence(cr), 4), f"{tid} 읽기"):
                                        changed = True
                            if action in ("write", "admin", "modify_permissions", "take_ownership"):
                                if add_step("R3", Fact.data_access(did, "write"), (actor_fact,) + kp, round(base_p * obj_confidence(cr), 4), f"{tid} 쓰기"):
                                    changed = True
                    elif ttype == "data":
                        if action in ("read", "admin", "modify_permissions", "take_ownership"):
                            if add_step("R3", Fact.data_access(tid, "read"), (actor_fact,) + kp, base_p, "직접 데이터 읽기"):
                                changed = True
                        if action in ("write", "admin", "modify_permissions", "take_ownership"):
                            if add_step("R3", Fact.data_access(tid, "write"), (actor_fact,) + kp, base_p, "직접 데이터 쓰기"):
                                changed = True
                    elif ttype in ("host", "service") and action in ("execute", "admin", "modify_permissions", "take_ownership"):
                        lvl = "admin" if action in ("admin", "modify_permissions", "take_ownership") else "user"
                        if add_step("R3", Fact.foothold(tid, lvl), (actor_fact,) + kp, base_p, f"{actor_id} {action} on {tid}"):
                            changed = True
                    elif ttype == "policy" and action in ("write", "admin", "modify_permissions", "take_ownership"):
                        if add_step("R3", Fact.foothold(tid, "admin"), (actor_fact,) + kp, base_p, f"{actor_id} 정책 수정 권한"):
                            changed = True
                    elif ttype == "identity":
                        tkind = t_asset.get("kind")
                        if action in ("reset_credential", "delegate", "admin", "modify_permissions", "take_ownership"):
                            if add_step("R3", Fact.acts_as(tid), (actor_fact,) + kp, base_p, f"{actor_id} {action} → {tid}"):
                                changed = True
                        elif action == "add_member" and tkind == "group":
                            if add_step("R3", Fact.acts_as(tid), (actor_fact,) + kp, base_p, f"{actor_id} add_member → {tid}"):
                                changed = True

        # ---- R4: 실행 계정 (foothold(admin) + runs.as -> acts_as) ----
        for r in graph.by_type.get("runs", []):
            if "as" not in r:
                continue
            fh = _foothold_fact_for(facts, r["from"], "admin")
            if fh:
                if add_step("R4", Fact.acts_as(r["as"]), (fh,), obj_confidence(r), f"{r['from']} 실행 계정 {r['as']}"):
                    changed = True

        # ---- R5: 로그인 세션 (foothold(admin) + session -> acts_as) ----
        for r in graph.by_type.get("session", []):
            fh = _foothold_fact_for(facts, r["to"], "admin")
            if not fh:
                continue
            ident = graph.assets.get(r["from"])
            if ident and ident.get("type") == "identity" and ident.get("kind") != "group":
                freq, fconf, _ = unwrap_attr(r.get("frequency"), "unknown")
                fp = FREQUENCY_PROB.get(str(freq), 0.40) * (fconf if fconf > 0 else 1.0)
                if add_step("R5", Fact.acts_as(r["from"]), (fh,), round(obj_confidence(r) * fp, 4), f"{r['to']} 세션 탈취"):
                    changed = True

        # ---- R6: 보관된 자격증명 (foothold(admin) + stores -> has_credential) ----
        for r in graph.by_type.get("stores", []):
            fh = _foothold_fact_for(facts, r["from"], "admin")
            if fh:
                tgt = graph.assets.get(r["to"])
                if tgt and tgt.get("type") == "credential":
                    if add_step("R6", Fact.has_credential(r["to"]), (fh,), obj_confidence(r), f"{r['from']} 보관 자격증명"):
                        changed = True

        # ---- R7: 자격증명 사용 (has_credential + grants -> acts_as) ----
        for f in list(facts):
            if f.kind != "has_credential":
                continue
            cid = f.args[0]
            for r in graph.by_type.get("grants", []):
                if r["from"] == cid:
                    if add_step("R7", Fact.acts_as(r["to"]), (f,), obj_confidence(r), f"{cid} → {r['to']}"):
                        changed = True

        # ---- R8: 그룹 장악 (도메인 컨트롤러 / manages group -> controls(group)) ----
        for r in graph.by_type.get("manages", []):
            if not is_group_ref(r["to"]):
                continue
            fh = _foothold_fact_for(facts, r["from"], "admin")
            if fh:
                gid = strip_group_prefix(r["to"])
                if add_step("R8", Fact.controls(gid), (fh,), obj_confidence(r), f"{r['from']} → group:{gid}"):
                    changed = True

        # role: domain_controller 호스트의 admin 거점 → 소속 directory_domain 장악
        for aid, lvl in list(best_fh.items()):
            if not priv_at_least(lvl, "admin"):
                continue
            a = graph.assets.get(aid)
            if a and a.get("type") == "host" and a.get("role") == "domain_controller":
                fh = Fact.foothold(aid, lvl)
                for gid in a.get("groups") or []:
                    g = graph.groups.get(gid)
                    if g and g.get("kind") == "directory_domain":
                        if add_step("R8", Fact.controls(gid), (fh,), 0.98, f"DC {aid} → 도메인 {gid} 장악"):
                            changed = True

        for f in list(facts):
            if f.kind != "controls":
                continue
            gid = f.args[0]
            # 하위 그룹 전파
            for cg_id, cg in graph.groups.items():
                if cg.get("parent") == gid:
                    if add_step("R8", Fact.controls(cg_id), (f,), 1.0, f"하위 그룹 {cg_id}"):
                        changed = True
            # 그룹 소속 호스트에 대한 관리자 거점
            for aid in graph.assets_in_group(gid):
                a = graph.assets.get(aid)
                kp = _know_prem(facts, knowledge, aid)
                if a and a.get("type") == "host" and kp is not None:
                    if add_step("R8", Fact.foothold(aid, "admin"), (f,) + kp, 0.95, f"그룹 {gid} 장악으로 {aid} 제어"):
                        changed = True

        # ---- R9: 데이터 접근 (foothold(admin) on store or hosting server + contains) ----
        for r in graph.by_type.get("contains", []):
            store_id, data_id = r["from"], r["to"]
            holders = [store_id] + [h for h, _ in hosted_by.get(store_id, [])]
            for hid in holders:
                fh = _foothold_fact_for(facts, hid, "admin")
                if not fh:
                    continue
                if r.get("encrypted") and r.get("key_ref"):
                    kf = Fact.has_credential(r["key_ref"])
                    if kf in facts:
                        if add_step("R9", Fact.data_access(data_id, "read"), (fh, kf), obj_confidence(r), f"{store_id} 복호화 읽기"):
                            changed = True
                else:
                    if add_step("R9", Fact.data_access(data_id, "read"), (fh,), obj_confidence(r), f"{store_id} 데이터 읽기"):
                        changed = True
                if add_step("R9", Fact.data_access(data_id, "write"), (fh,), obj_confidence(r), f"{store_id} 데이터 쓰기"):
                    changed = True

        # ---- R10: 노출 서비스 침해 (reaches + runs -> foothold(user), 단독 managed_service 포함) ----
        for src_id, lvl in list(best_fh.items()):
            src_fact = Fact.foothold(src_id, lvl)
            for r in graph.by_type.get("runs", []):
                host_id, svc_id = r["from"], r["to"]
                if src_id == host_id:
                    continue
                kp = _know_prem(facts, knowledge, host_id)
                if kp is None:
                    kp = _know_prem(facts, knowledge, svc_id)
                if kp is None:
                    continue
                svc = graph.assets.get(svc_id, {})
                port = svc.get("port")
                proto = svc.get("protocol")
                matches = graph.can_reach(src_id, host_id, port=port, protocol=proto)
                if matches:
                    p = round(_exploit_prob(graph, host_id, svc_id, capability) * max(m.confidence for m in matches), 4)
                    if add_step("R10", Fact.foothold(host_id, "user"), (src_fact,) + kp, p, f"{src_id} → {host_id}:{svc_id}"):
                        changed = True
            # 호스트가 없는 관리형 서비스(managed_service 등)에 직접 도달
            for svc_id, svc in graph.assets.items():
                if svc.get("type") != "service" or svc_id in svc_hosts or src_id == svc_id:
                    continue
                kp = _know_prem(facts, knowledge, svc_id)
                if kp is None:
                    continue
                matches = graph.can_reach(src_id, svc_id, port=svc.get("port"), protocol=svc.get("protocol"))
                if matches:
                    p = round(_exploit_prob(graph, None, svc_id, capability) * max(m.confidence for m in matches), 4)
                    if add_step("R10", Fact.foothold(svc_id, "user"), (src_fact,) + kp, p, f"{src_id} → {svc_id}"):
                        changed = True

        # ---- R10b: 로컬 권한 상승 (foothold(user) -> foothold(admin)) ----
        for aid, lvl in list(best_fh.items()):
            a = graph.assets.get(aid)
            if a and a.get("type") == "host" and lvl == "user":
                src_fact = Fact.foothold(aid, "user")
                p = _lpe_prob(graph, aid, capability)
                if add_step("R10b", Fact.foothold(aid, "admin"), (src_fact,), p, f"{aid} 로컬 권한 상승"):
                    changed = True

        # ---- R11: 관리 주체 (foothold(admin) + manages -> 피관리 자산 foothold(admin)) ----
        for r in graph.by_type.get("manages", []):
            if is_group_ref(r["to"]):
                continue
            fh = _foothold_fact_for(facts, r["from"], "admin")
            if not fh:
                continue
            for tid in graph.expand_ref_assets(r["to"]):
                kp = _know_prem(facts, knowledge, tid)
                if kp is not None:
                    if add_step("R11", Fact.foothold(tid, "admin"), (fh,) + kp, obj_confidence(r), f"{r['from']} manages {tid}"):
                        changed = True

    goals = _evaluate_goals(graph, facts, derivs, egress)
    return VariantResult(
        profile_id=profile.get("id", "default"),
        knowledge=knowledge,
        egress=egress,
        facts=facts,
        derivations=dict(derivs),
        goals=goals,
    )


def _egress_prob(graph: InfraGraph, facts: set[Fact], data_id: str, egress: str) -> tuple[bool, float]:
    """data_id를 외부로 반출할 수 있는지(assumed_open vs from_ir) 판정한다."""
    if Fact.data_access(data_id, "read") not in facts:
        return False, 0.0
    if egress == "assumed_open":
        return True, 1.0

    # from_ir: 데이터를 읽을 수 있는 저장소/호스트(또는 거점이 있는 자산) 중 external로 나가는 경로 확인
    best_fh = _best_footholds(facts)
    best_p = 0.0
    # 1) 데이터를 담은 저장소/호스트에서 직접 external로 나가는 경우
    for cr in graph.by_type.get("contains", []):
        if cr["to"] != data_id:
            continue
        store_id = cr["from"]
        candidates = [store_id] + [r["from"] for r in graph.by_type.get("hosts", []) if r["to"] == store_id]
        for cid in candidates:
            for m in graph.has_egress_to_external(cid):
                best_p = max(best_p, m.confidence)
    # 2) 또는 공격자가 확보한 거점(user 이상) 중 external로 나가는 경로가 있는 경우
    if best_p == 0.0:
        for aid, lvl in best_fh.items():
            if priv_at_least(lvl, "user"):
                for m in graph.has_egress_to_external(aid):
                    best_p = max(best_p, m.confidence)
    return (best_p > 0.0), best_p


def _fact_prob(fact: Fact, derivs: dict[Fact, list[DerivationStep]], visiting: set[Fact] | None = None) -> float:
    """DAG 위에서 사실의 단순 확률을 계산한다 (AND=곱, OR=noisy-OR, 순환 방지)."""
    if visiting is None:
        visiting = set()
    if fact in visiting:
        return 0.0
    steps = derivs.get(fact)
    if not steps:
        return 0.0

    visiting = visiting | {fact}
    fail_all = 1.0
    for step in steps:
        p = step.prob
        for prem in step.premises:
            p *= _fact_prob(prem, derivs, visiting)
        fail_all *= max(0.0, 1.0 - p)
    return round(1.0 - fail_all, 4)


def _sample_path(fact: Fact, derivs: dict[Fact, list[DerivationStep]], visiting: set[Fact] | None = None) -> list[DerivationStep]:
    """가장 확률이 높은 단일 유도 경로를 추출한다."""
    if visiting is None:
        visiting = set()
    if fact in visiting:
        return []
    steps = derivs.get(fact)
    if not steps:
        return []
    visiting = visiting | {fact}

    best_step = max(steps, key=lambda s: s.prob)
    path: list[DerivationStep] = []
    for prem in best_step.premises:
        path.extend(_sample_path(prem, derivs, visiting))
    path.append(best_step)
    return path


def _eval_condition(
    cond: dict[str, Any],
    graph: InfraGraph,
    facts: set[Fact],
    derivs: dict[Fact, list[DerivationStep]],
    egress: str,
) -> tuple[bool, float, list[list[DerivationStep]]]:
    if "all" in cond:
        probs: list[float] = []
        paths: list[list[DerivationStep]] = []
        for sub in cond["all"]:
            ok, p, sp = _eval_condition(sub, graph, facts, derivs, egress)
            if not ok:
                return False, 0.0, []
            probs.append(p)
            paths.extend(sp)
        total_p = 1.0
        for p in probs:
            total_p *= p
        return True, round(total_p, 4), paths

    if "any" in cond:
        fail_all = 1.0
        any_ok = False
        paths = []
        for sub in cond["any"]:
            ok, p, sp = _eval_condition(sub, graph, facts, derivs, egress)
            if ok:
                any_ok = True
                fail_all *= max(0.0, 1.0 - p)
                paths.extend(sp)
        return any_ok, round(1.0 - fail_all, 4) if any_ok else 0.0, paths

    if "exfiltrated" in cond:
        did = cond["exfiltrated"]
        eg_ok, eg_p = _egress_prob(graph, facts, did, egress)
        if not eg_ok:
            return False, 0.0, []
        f = Fact.data_access(did, "read")
        fp = _fact_prob(f, derivs)
        return True, round(fp * eg_p, 4), [_sample_path(f, derivs)]

    if "read" in cond:
        f = Fact.data_access(cond["read"], "read")
        ok = f in facts
        return ok, _fact_prob(f, derivs) if ok else 0.0, [_sample_path(f, derivs)] if ok else []

    if "tampered" in cond or "destroyed" in cond:
        did = cond.get("tampered") or cond.get("destroyed")
        f = Fact.data_access(str(did), "write")
        ok = f in facts
        return ok, _fact_prob(f, derivs) if ok else 0.0, [_sample_path(f, derivs)] if ok else []

    if "disrupted" in cond:
        biz_id = cond["disrupted"]
        deps = [r["to"] for r in graph.by_type.get("depends_on", []) if r["from"] == biz_id]
        # 직접 거점 또는 의존 자산 중 하나의 admin 이상 거점
        candidates = [biz_id] + deps
        fail_all = 1.0
        any_ok = False
        paths: list[list[DerivationStep]] = []
        for cid in candidates:
            # 호스트 또는 해당 서비스를 실행하는 호스트의 admin 거점 확인
            check_ids = [cid] + [r["from"] for r in graph.by_type.get("runs", []) if r["to"] == cid]
            for hid in check_ids:
                fh = _foothold_fact_for(facts, hid, "admin")
                if fh:
                    any_ok = True
                    p = _fact_prob(fh, derivs)
                    fail_all *= max(0.0, 1.0 - p)
                    paths.append(_sample_path(fh, derivs))
        return any_ok, round(1.0 - fail_all, 4) if any_ok else 0.0, paths

    if "acts_as" in cond:
        f = Fact.acts_as(cond["acts_as"])
        ok = f in facts
        return ok, _fact_prob(f, derivs) if ok else 0.0, [_sample_path(f, derivs)] if ok else []

    if "has_credential" in cond:
        f = Fact.has_credential(cond["has_credential"])
        ok = f in facts
        return ok, _fact_prob(f, derivs) if ok else 0.0, [_sample_path(f, derivs)] if ok else []

    if "controls" in cond:
        gid = strip_group_prefix(cond["controls"])
        f = Fact.controls(gid)
        ok = f in facts
        return ok, _fact_prob(f, derivs) if ok else 0.0, [_sample_path(f, derivs)] if ok else []

    return False, 0.0, []


def _evaluate_goals(
    graph: InfraGraph,
    facts: set[Fact],
    derivs: dict[Fact, list[DerivationStep]],
    egress: str,
) -> list[GoalOutcome]:
    raw_goals = graph.doc.get("impact_goals") or generate_auto_goals(graph)
    outcomes: list[GoalOutcome] = []
    for g in raw_goals:
        ok, p, paths = _eval_condition(g["condition"], graph, facts, derivs, egress)
        imp = g.get("impact") or {}
        lvl = imp.get("level", "medium")
        outcomes.append(GoalOutcome(
            goal_id=g["id"],
            harm=g["harm"],
            achieved=ok,
            impact_level=lvl,
            prob=p,
            paths=paths,
        ))
    return outcomes


def analyze_doc(doc: dict[str, Any]) -> list[VariantResult]:
    """IR 문서의 모든 공격자 프로필 × 분석 변형을 실행한다."""
    graph = InfraGraph(doc)
    profiles = doc.get("attacker_profiles")
    if not profiles:
        ext_ids = [aid for aid, a in graph.assets.items() if a.get("type") == "external"]
        if ext_ids:
            profiles = [{"id": "external", "start": ext_ids, "capability": "medium"}]
        else:
            # 외부 노드가 없는 내부 랩/망 IR: 워크스테이션·점프호스트·첫 호스트를 자동 후보로 제안
            ws_ids = [
                aid for aid, a in graph.assets.items()
                if a.get("type") == "host" and a.get("role") in ("workstation", "jump_host")
            ]
            if not ws_ids:
                ws_ids = [aid for aid, a in graph.assets.items() if a.get("type") == "host"][:1]
            profiles = [{
                "id": "insider-auto",
                "start": ws_ids,
                "initial_privilege": "user",
                "capability": "medium",
            }]
    results: list[VariantResult] = []
    for prof in profiles:
        for var in profile_variants(prof):
            results.append(run_variant(graph, prof, var["knowledge"], var["egress"]))
    return results
