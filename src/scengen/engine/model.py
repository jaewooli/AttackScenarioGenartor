"""공격자 상태 모델(Fact)과 시나리오 DAG 기본 자료구조.

docs/attacker-state.md 기반:
- 공격자 상태 = 단조 증가하는 사실(Fact) 집합
- 각 사실은 어떤 규칙(Step)의 어떤 전제(premises)로부터 유도되었는지 기록한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PRIVILEGE_ORDER: dict[str, int] = {
    "none": 0,
    "restricted": 1,
    "user": 2,
    "admin": 3,
    "system": 4,
}


# attacker_profile.capability → 역량 계수 (docs/rule-dsl.md 5장). 얇은 엔진과 규칙 평가기가 같이 쓴다
CAPABILITY_FACTOR: dict[str, float] = {
    "low": 0.45,
    "medium": 0.70,
    "high": 0.88,
    "advanced": 0.96,
}


def priv_at_least(have: str, need: str) -> bool:
    """권한 수준이 요구 수준 이상인지 반환한다."""
    return PRIVILEGE_ORDER.get(have, -1) >= PRIVILEGE_ORDER.get(need, 99)


@dataclass(frozen=True)
class Fact:
    """공격자 상태의 원자적 사실."""

    kind: str
    args: tuple[str, ...]

    def __str__(self) -> str:
        return f"{self.kind}({', '.join(self.args)})"

    @classmethod
    def foothold(cls, asset: str, level: str) -> Fact:
        return cls("foothold", (asset, level))

    @classmethod
    def acts_as(cls, identity: str) -> Fact:
        return cls("acts_as", (identity,))

    @classmethod
    def has_credential(cls, cred: str) -> Fact:
        return cls("has_credential", (cred,))

    @classmethod
    def controls(cls, group: str) -> Fact:
        return cls("controls", (group,))

    @classmethod
    def data_access(cls, data: str, mode: str) -> Fact:
        return cls("data_access", (data, mode))

    @classmethod
    def knows(cls, target: str) -> Fact:
        return cls("knows", (target,))


@dataclass(frozen=True)
class DerivationStep:
    """하나의 사실을 유도하는 규칙 적용 1건 (AND 노드)."""

    rule_id: str
    conclusion: Fact
    premises: tuple[Fact, ...]
    prob: float
    note: str = ""
    source_relations: tuple[str, ...] = ()


@dataclass
class GoalOutcome:
    """개별 피해 목표의 판정 결과."""

    goal_id: str
    harm: str
    achieved: bool
    impact_level: str
    prob: float
    paths: list[list[DerivationStep]] = field(default_factory=list)


@dataclass
class VariantResult:
    """(프로필 × knowledge × egress) 변형 1건의 실행 결과."""

    profile_id: str
    knowledge: str
    egress: str
    facts: set[Fact] = field(default_factory=set)
    derivations: dict[Fact, list[DerivationStep]] = field(default_factory=dict)
    goals: list[GoalOutcome] = field(default_factory=list)


def unwrap_attr(val: Any, default: Any = None) -> tuple[Any, float, str]:
    """Attr 래퍼 또는 단순 값에서 (value, confidence, source)를 꺼낸다."""
    if val is None:
        return default, 0.0, "unknown"
    if isinstance(val, dict) and ("source" in val or "value" in val or "distribution" in val):
        src = val.get("source", "declared")
        conf = float(val.get("confidence", 1.0 if src == "declared" else 0.5))
        if "value" in val:
            return val["value"], conf, src
        if "distribution" in val:
            return val["distribution"], conf, src
        return default, conf, src
    return val, 1.0, "declared"


def obj_confidence(obj: dict[str, Any]) -> float:
    """객체(관계 등)의 존재 확신도를 반환한다."""
    src = obj.get("source", "declared")
    if "confidence" in obj:
        return float(obj["confidence"])
    return 1.0 if src == "declared" else 0.5
