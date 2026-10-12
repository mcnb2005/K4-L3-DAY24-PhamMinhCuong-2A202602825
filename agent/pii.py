"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "EMAIL",
        re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])", re.I),
    ),
    (
        "VN_CCCD",
        re.compile(r"\bCCCD\b[^\d]{0,24}(?P<value>\d{12})(?!\d)", re.I),
    ),
    (
        "VN_PHONE",
        re.compile(
            r"(?:S(?:Ố|O)\s*ĐIỆN\s*THOẠI|SĐT|SDT)[^\d]{0,32}"
            r"(?P<value>0\d(?:[ .-]?\d){8,9})(?!\d)",
            re.I,
        ),
    ),
    (
        "VN_BANK_ACCOUNT",
        re.compile(
            r"(?:STK|S(?:Ố|O)\s*TÀI\s*KHOẢN)[^\d]{0,32}"
            r"(?P<value>\d(?:[ .-]?\d){7,15})(?!\d)",
            re.I,
        ),
    ),
)


def _span(match: re.Match[str]) -> tuple[int, int]:
    """Return the captured value span, or the whole match for e-mail."""
    return match.span("value") if "value" in match.re.groupindex else match.span()


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    occupied: list[tuple[int, int]] = []

    for entity_type, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = _span(match)
            if any(start < old_end and old_start < end for old_start, old_end in occupied):
                continue
            entities.append({"type": entity_type, "start": start, "end": end})
            occupied.append((start, end))

    return sorted(entities, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    redacted = text
    for entity in reversed(detect(text)):
        marker = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + marker + redacted[entity["end"] :]
    return redacted
