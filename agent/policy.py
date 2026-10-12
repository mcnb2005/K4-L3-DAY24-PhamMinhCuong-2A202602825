"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    # The minimum data-egress rule is deliberately evaluated first. It must
    # remain effective even when an otherwise fully-authorized principal calls.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data may not cross an egress-enabled boundary"

    try:
        principals = json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "trusted principal registry is unavailable"

    principal = principals.get(context.principal_id)
    if principal is None:
        return False, f"unknown principal: {context.principal_id or '<empty>'}"

    if not context.requested_tool:
        return False, "requested tool is missing"
    if not context.request_purpose:
        return False, "request purpose is missing"
    if context.request_purpose not in principal.get("purposes", []):
        return False, f"purpose {context.request_purpose!r} is not allowed for {context.principal_id}"

    if not context.expires_at:
        return False, "delegation expiry is missing"
    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            return False, "delegation expiry must include a timezone"
        if expires_at <= datetime.now(timezone.utc):
            return False, "delegation has expired"
    except ValueError:
        return False, "delegation expiry is not valid ISO-8601"

    effective_tools = set(principal.get("allowed_tools", ())) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective_tools &= set(context.parent_scopes)
    if context.requested_tool not in effective_tools:
        return False, (
            f"tool {context.requested_tool!r} is outside the effective delegated scope "
            f"for {context.principal_id}"
        )

    return True, (
        f"principal {context.principal_id} may use {context.requested_tool} "
        f"for purpose {context.request_purpose}"
    )
