"""목표 자동 생성기 (WBS 3.2, docs/ir-spec.md 8.4).

사용자가 impact_goals를 생략하면 IR의 data, business_service, identifiers 겹침을
바탕으로 exfiltrate, tamper, disrupt 및 결합 목표를 자동 생성한다.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Any

from .graph import InfraGraph
from .model import unwrap_attr

IMPACT_ORDER = ["low", "medium", "high", "critical"]
HIGH_SENSITIVE_CATS = {
    "sensitive_personal",
    "unique_identifier",
    "payment",
    "credit",
    "credential_material",
}
HIGH_CATS = {"personal", "financial", "health", "trade_secret", "source_code"}


def _bump_impact(level: str) -> str:
    idx = IMPACT_ORDER.index(level) if level in IMPACT_ORDER else 1
    return IMPACT_ORDER[min(len(IMPACT_ORDER) - 1, idx + 1)]


def _infer_data_impact(asset: dict[str, Any]) -> tuple[str, str]:
    """data 자산의 categories, environment, regulations로부터 (level, source)를 추정한다."""
    crit = asset.get("criticality")
    if crit in ("low", "medium", "high"):
        return crit, "declared"
    if crit == "crown_jewel":
        return "critical", "declared"

    cats_raw, _, cats_src = unwrap_attr(asset.get("categories"), [])
    cats = set(cats_raw) if isinstance(cats_raw, list) else set()
    env, _, _ = unwrap_attr(asset.get("environment"), "prod")
    regs, _, _ = unwrap_attr(asset.get("regulations"), [])

    if "public" in cats or env == "test":
        return "low", "assumed"

    if cats & HIGH_SENSITIVE_CATS:
        level = "high"
    elif cats & HIGH_CATS:
        level = "medium"
    else:
        level = "medium"

    if regs and level in ("low", "medium"):
        level = _bump_impact(level)
    if env == "staging" and level != "low":
        idx = IMPACT_ORDER.index(level)
        level = IMPACT_ORDER[max(0, idx - 1)]

    src = "inferred" if cats_src == "inferred" else "assumed"
    return level, src


def _infer_service_impact(asset: dict[str, Any]) -> tuple[str, str]:
    crit = asset.get("criticality")
    if crit in ("low", "medium", "high"):
        return crit, "declared"
    if crit == "crown_jewel":
        return "critical", "declared"

    dt = asset.get("downtime_impact") or {}
    if isinstance(dt, dict):
        per_hour = dt.get("per_hour")
        if per_hour in IMPACT_ORDER:
            return per_hour, "declared"
    return "medium", "assumed"


def generate_auto_goals(graph: InfraGraph) -> list[dict[str, Any]]:
    """스펙 8.4 규칙에 따라 자동 피해 목표 목록을 생성한다."""
    goals: list[dict[str, Any]] = []
    data_impacts: dict[str, str] = {}
    by_identifier: dict[str, list[str]] = defaultdict(list)

    for aid, asset in graph.assets.items():
        atype = asset.get("type")
        if atype == "data":
            level, src = _infer_data_impact(asset)
            data_impacts[aid] = level
            cats_raw, _, _ = unwrap_attr(asset.get("categories"), [])
            cats = set(cats_raw) if isinstance(cats_raw, list) else set()

            # 공개 데이터는 유출(exfiltrate) 목표에서 제외하되 변조(tamper)는 포함
            if "public" not in cats:
                goals.append({
                    "id": f"auto-exfil-{aid}",
                    "harm": "exfiltrate",
                    "condition": {"exfiltrated": aid},
                    "impact": {"level": level, "source": src},
                })
            goals.append({
                "id": f"auto-tamper-{aid}",
                "harm": "tamper",
                "condition": {"tampered": aid},
                "impact": {"level": level, "source": src},
            })

            if "public" not in cats:
                for ident_key in asset.get("identifiers") or []:
                    by_identifier[str(ident_key)].append(aid)

        elif atype == "business_service":
            level, src = _infer_service_impact(asset)
            goals.append({
                "id": f"auto-disrupt-{aid}",
                "harm": "disrupt",
                "condition": {"disrupted": aid},
                "impact": {"level": level, "source": src},
            })

    # identifiers 겹침 기반 결합 목표 후보 생성
    seen_pairs: set[tuple[str, str]] = set()
    for ident_key, aids in by_identifier.items():
        if len(aids) < 2:
            continue
        for d1, d2 in combinations(sorted(set(aids)), 2):
            pair = (d1, d2)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            max_lvl = max(
                data_impacts.get(d1, "medium"),
                data_impacts.get(d2, "medium"),
                key=lambda lv: IMPACT_ORDER.index(lv),
            )
            goals.append({
                "id": f"auto-combined-{d1}-{d2}",
                "harm": "exfiltrate",
                "description": f"식별자({ident_key}) 겹침 결합 유출: {d1} + {d2}",
                "condition": {"all": [{"exfiltrated": d1}, {"exfiltrated": d2}]},
                "impact": {"level": _bump_impact(max_lvl), "source": "assumed"},
            })

    return goals
