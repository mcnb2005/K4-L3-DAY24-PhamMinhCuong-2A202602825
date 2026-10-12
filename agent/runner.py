"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_PATH = Path(__file__).resolve().parent.parent / "data" / "customers.json"
PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"
_TICKET_NAME = re.compile(r"^ticket-(\d+)\.md$", re.I)


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _args_hash(arguments: object) -> str:
    canonical = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _decision_entry(
    *,
    context: policy.PolicyContext,
    decision: str,
    reason: str,
    run_id: str,
    args: object,
) -> dict:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": context.agent_owner,
        "run_id": run_id,
        "tool": context.requested_tool,
        "args_hash": _args_hash(args),
        "classification": context.data_classification,
        "decision": decision,
        "reason": reason,
        "on_behalf_of": context.principal_id,
        "expires_at": context.expires_at,
    }


def _authorize(
    context: policy.PolicyContext,
    *,
    run_id: str,
    args: object,
    ledger_path: Path,
) -> bool:
    allowed, reason = policy.check(context)
    ledger.append(
        _decision_entry(
            context=context,
            decision="allow" if allowed else "deny",
            reason=reason,
            run_id=run_id,
            args=args,
        ),
        ledger_path,
    )
    return allowed


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Derive typed IDs only from trusted filenames, never document text."""
    ids: set[int] = set()
    for doc in docs:
        match = _TICKET_NAME.fullmatch(str(doc.get("id", "")))
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Build the trusted ticket-to-customer mapping from fixture metadata."""
    customers = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
    requested = set(ticket_ids)
    return sorted(
        str(customer["customer_id"])
        for customer in customers
        if requested.intersection(int(item) for item in customer.get("related_tickets", ()))
    )


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    output_dir = Path(log_dir) if log_dir is not None else REPORTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = output_dir / "ledger.jsonl"

    run_root = uuid.uuid4().hex
    run_a_id = f"{run_root}/run-a"
    run_b_id = f"{run_root}/run-b"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    principals = json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    parent_scopes = tuple(principals.get(principal_id, {}).get("allowed_tools", ()))

    # Run A: untrusted corpus only. It has neither private-store nor egress scope.
    search_context = policy.PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        parent_scopes=(),
        expires_at=expires_at,
    )
    docs: list[dict] = []
    if _authorize(search_context, run_id=run_a_id, args={"query": message}, ledger_path=ledger_path):
        docs = tools.search_docs(message)

    combined_text = "\n\n".join(str(doc.get("text", "")) for doc in docs)
    injected = llm.find_injection(combined_text)

    # This typed list is the entire Run A -> Run B boundary. No document text,
    # embedded customer ID, URL, or attacker instruction crosses it.
    ticket_ids = _ticket_ids(docs)
    customer_ids = _customers_for_tickets(ticket_ids)

    # Run B: private-store access, delegated on behalf of the selected principal.
    records: list[dict] = []
    for customer_id in customer_ids:
        read_context = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("read_customer",),
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        if _authorize(
            read_context,
            run_id=run_b_id,
            args={"customer_id": customer_id},
            ledger_path=ledger_path,
        ):
            try:
                records.append(tools.read_customer(customer_id))
            except tools.ToolError:
                continue

    # Preserve the attempted malicious behavior as auditable evidence, but put
    # the policy enforcement point immediately before the real network tool.
    if injected is not None and records:
        post_context = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("http_post",),
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        body = {"records": records}
        if _authorize(
            post_context,
            run_id=run_b_id,
            args={"url": injected.target_url, "body": body},
            ledger_path=ledger_path,
        ):
            tools.http_post(injected.target_url, body)

    # Any corpus PII is redacted before a model-facing response boundary.
    safe_docs = [dict(doc, text=pii.redact(str(doc.get("text", "")))) for doc in docs]
    return llm.summarize(safe_docs)
