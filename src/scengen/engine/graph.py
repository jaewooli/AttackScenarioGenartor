"""IR 그래프 인덱스와 그룹 상속·도달성·설정 해석기."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .model import obj_confidence, unwrap_attr

GROUP_PREFIX = "group:"


def is_group_ref(ref: str) -> bool:
    return ref.startswith(GROUP_PREFIX)


def strip_group_prefix(ref: str) -> str:
    return ref[len(GROUP_PREFIX) :] if is_group_ref(ref) else ref


@dataclass(frozen=True)
class ReachMatch:
    """도달성 엣지 매칭 결과."""

    src_asset: str
    dst_asset: str
    confidence: float
    relation: dict[str, Any]


class InfraGraph:
    """IR 문서를 엔진이 조회하기 쉬운 그래프 구조로 색인한다."""

    def __init__(self, doc: dict[str, Any]) -> None:
        self.doc = doc
        self.context: dict[str, Any] = doc.get("context") or {}
        self.defaults: dict[str, Any] = self.context.get("defaults") or {}

        excluded = set((self.context.get("scope") or {}).get("exclude") or [])
        self.excluded_groups = {strip_group_prefix(x) for x in excluded if is_group_ref(x)}
        self.excluded_assets = {x for x in excluded if not is_group_ref(x)}

        self.groups: dict[str, dict[str, Any]] = {
            g["id"]: g for g in (doc.get("groups") or []) if g["id"] not in self.excluded_groups
        }
        self.assets: dict[str, dict[str, Any]] = {
            a["id"]: a
            for a in (doc.get("assets") or [])
            if a["id"] not in self.excluded_assets
            and not (set(a.get("groups") or []) & self.excluded_groups)
        }
        self.relations: list[dict[str, Any]] = [
            r
            for r in (doc.get("relations") or [])
            if not self._is_excluded_ref(r["from"]) and not self._is_excluded_ref(r["to"])
        ]

        self.by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        # (관계 타입, 끝점 참조) → by_type[타입] 안의 위치. 규칙 평가기가 관계 전체를 훑지 않도록
        self.rel_index_from: dict[tuple[str, str], list[int]] = defaultdict(list)
        self.rel_index_to: dict[tuple[str, str], list[int]] = defaultdict(list)
        for r in self.relations:
            lst = self.by_type[r["type"]]
            self.rel_index_from[(r["type"], r["from"])].append(len(lst))
            self.rel_index_to[(r["type"], r["to"])].append(len(lst))
            lst.append(r)

        # 그룹별 routes_via 원본 매핑 (경유 장비 제외 여부 판정용)
        self._group_routes_via: dict[str, list[str]] = defaultdict(list)
        for r in doc.get("relations") or []:
            if r.get("type") == "routes_via":
                self._group_routes_via[strip_group_prefix(r["from"])].append(r["to"])

        # 그룹 조상 캐시 (자신 포함)
        self._group_ancestors: dict[str, set[str]] = {}
        for gid in self.groups:
            self._group_ancestors[gid] = self._compute_ancestors(gid)

        # 자산별 유효 그룹 집합 (직접 소속 + 조상 그룹)
        self._asset_groups: dict[str, set[str]] = {}
        for aid, asset in self.assets.items():
            eff: set[str] = set()
            for gid in asset.get("groups") or []:
                eff |= self._group_ancestors.get(gid, {gid})
            self._asset_groups[aid] = eff

    def _is_excluded_ref(self, ref: str) -> bool:
        if is_group_ref(ref):
            return strip_group_prefix(ref) in self.excluded_groups
        return ref in self.excluded_assets

    def _compute_ancestors(self, gid: str) -> set[str]:
        seen: set[str] = set()
        cur: str | None = gid
        while cur and cur not in seen:
            seen.add(cur)
            g = self.groups.get(cur)
            cur = g.get("parent") if g else None
        return seen

    def asset_groups(self, asset_id: str) -> set[str]:
        return self._asset_groups.get(asset_id, set())

    def assets_in_group(self, group_id: str) -> list[str]:
        gid = strip_group_prefix(group_id)
        return [aid for aid, gs in self._asset_groups.items() if gid in gs]

    def matches_target(self, node_id: str, ref: str) -> bool:
        """자산 node_id가 관계 끝점 ref(자산 id 또는 group:id)에 해당하는지 판정."""
        if is_group_ref(ref):
            return strip_group_prefix(ref) in self.asset_groups(node_id)
        return node_id == ref

    def expand_ref_assets(self, ref: str) -> list[str]:
        """참조(자산 id 또는 group:id)가 가리키는 모든 자산 id 목록."""
        if is_group_ref(ref):
            return self.assets_in_group(ref)
        return [ref] if ref in self.assets else []

    def get_config(self, asset_id: str, key: str, default: Any = None) -> tuple[Any, float, str]:
        """우선순위(자산 > 그룹 > context.defaults > 기본값)로 설정 값을 조회한다."""
        asset = self.assets.get(asset_id)
        if asset:
            cfg = asset.get("config") or {}
            if key in cfg:
                return unwrap_attr(cfg[key], default)
            # 직접 소속 그룹부터 조상 순서로 탐색
            queue = list(asset.get("groups") or [])
            visited: set[str] = set()
            while queue:
                gid = queue.pop(0)
                if gid in visited:
                    continue
                visited.add(gid)
                g = self.groups.get(gid)
                if not g:
                    continue
                gcfg = g.get("config") or {}
                if key in gcfg:
                    return unwrap_attr(gcfg[key], default)
                if g.get("parent"):
                    queue.append(g["parent"])
        if key in self.defaults:
            return unwrap_attr(self.defaults[key], default)
        return default, 0.0, "unknown"

    def can_reach(
        self,
        src_asset: str,
        dst_asset: str,
        port: int | None = None,
        protocol: str | None = None,
    ) -> list[ReachMatch]:
        """src_asset에서 dst_asset(특정 포트·프로토콜 옵션)으로 도달 가능한 reaches 엣지 목록.

        via 경유 장비나 routes_via 라우팅 장비가 scope.exclude로 제외된 경우 도달 불가로 처리한다.
        """
        if src_asset == dst_asset:
            return [ReachMatch(src_asset, dst_asset, 1.0, {"type": "local"})]

        # 출발·도착 그룹 중 한쪽에만 속한 그룹에 routes_via가 지정되어 있고, 그 장비가 모두 제외된 경우 도달 불가
        src_groups = self.asset_groups(src_asset)
        dst_groups = self.asset_groups(dst_asset)
        for gid in (src_groups ^ dst_groups):
            route_devs = self._group_routes_via.get(gid)
            if route_devs and not any(d in self.assets for d in route_devs):
                return []

        # 출발 자산 자신 또는 소속 그룹에서 시작하는 reaches만 후보 (IR 순서 유지)
        pos: set[int] = set(self.rel_index_from.get(("reaches", src_asset), ()))
        for gid in src_groups:
            pos.update(self.rel_index_from.get(("reaches", GROUP_PREFIX + gid), ()))
        all_reaches = self.by_type.get("reaches", [])
        matches: list[ReachMatch] = []
        for r in (all_reaches[i] for i in sorted(pos)):
            if not self.matches_target(dst_asset, r["to"]):
                continue
            via = r.get("via")
            if via is not None and via not in self.assets:
                continue
            if port is not None and "ports" in r:
                ports = r["ports"]
                if isinstance(ports, list) and port not in ports:
                    continue
            if protocol is not None and "protocol" in r:
                r_proto = r["protocol"]
                if r_proto and r_proto != "any" and r_proto != protocol:
                    continue
            matches.append(ReachMatch(src_asset, dst_asset, obj_confidence(r), r))
        return matches

    def has_egress_to_external(self, src_asset: str) -> list[ReachMatch]:
        """src_asset에서 external 타입 자산으로 나가는 reaches 엣지가 있는지 확인."""
        externals = [aid for aid, a in self.assets.items() if a.get("type") == "external"]
        out: list[ReachMatch] = []
        for ext in externals:
            out.extend(self.can_reach(src_asset, ext))
        return out
