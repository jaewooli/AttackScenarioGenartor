"""스키마에 정의된 모든 IR 필드를 이름으로 나열한다.

필드 감사표(docs/ir-field-audit.md)가 스키마와 어긋나지 않는지 테스트에서 확인하는 데 쓴다.
이름 형식: <객체>.<필드>, 타입별 필드는 <객체>.<타입>.<필드>
(여러 타입이 공유하면 타입을 '+'로 잇는다. 예: asset.service+network_device.product)
"""

from __future__ import annotations

import json

from .validate import SCHEMA_PATH

OBJECTS = ("group", "asset", "relation", "impact_goal", "attacker_profile", "context")
STRUCTURAL = {"id", "type", "from", "to"}  # 모든 엔진 동작의 전제. 감사 대상에서 제외


def schema_fields() -> set[str]:
    defs = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["$defs"]
    names: set[str] = set()
    for obj in OBJECTS:
        node = defs[obj]
        for f in node.get("properties", {}):
            if f not in STRUCTURAL:
                names.add(f"{obj}.{f}")
        for sub in node.get("allOf", []):
            cond = sub.get("if", {}).get("properties", {}).get("type", {})
            types = cond.get("const") or cond.get("enum")
            if not types:
                continue
            tag = types if isinstance(types, str) else "+".join(types)
            for f in sub.get("then", {}).get("properties", {}):
                names.add(f"{obj}.{tag}.{f}")
    return names
