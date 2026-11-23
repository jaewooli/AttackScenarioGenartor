"""필드 감사표가 스키마와 어긋나지 않는지 확인한다.

스키마에 필드를 추가하거나 지우면 docs/ir-field-audit.md 의 표도 함께 고쳐야 통과한다.
"""

import re
from pathlib import Path

from scengen.ir.fields import schema_fields

AUDIT = Path(__file__).resolve().parents[1] / "docs" / "ir-field-audit.md"
VERDICTS = {"핵심", "핵심·사전분포 필수", "의미 미정", "메타", "보류"}

ROW = re.compile(r"^\| `([a-z_+.]+)` \|.*\| ([^|]+) \|\s*$")


def audit_rows() -> dict[str, str]:
    rows = {}
    for line in AUDIT.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m and "." in m.group(1) and m.group(1).split(".")[0] in {
            "group", "asset", "relation", "impact_goal", "attacker_profile", "context"
        }:
            rows[m.group(1)] = m.group(2).strip()
    return rows


def test_every_schema_field_is_audited():
    missing = schema_fields() - audit_rows().keys()
    assert not missing, f"감사표에 없는 필드: {sorted(missing)}"


def test_no_stale_audit_rows():
    stale = audit_rows().keys() - schema_fields()
    assert not stale, f"스키마에 없는데 감사표에 남은 필드: {sorted(stale)}"


def test_every_row_has_known_verdict():
    for field, verdict in audit_rows().items():
        base = verdict.split(" (")[0].strip()
        assert base in VERDICTS, f"{field}: 알 수 없는 판정 '{verdict}'"
