# Compliance mapping — checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 (Luật Bảo vệ dữ liệu cá nhân) | Nhận diện/redact CCCD, số điện thoại, STK và email; phân loại hồ sơ là `restricted`; chặn egress. | `agent/pii.py:69`, `agent/pii.py:84`, `agent/policy.py:64`, `agent/runner.py:241`, `reports/attack-after.log` (0 byte) | Chỉ là dữ liệu synthetic và control kỹ thuật trong lab; chưa phải đánh giá tuân thủ pháp lý đầy đủ. |
| NĐ 356/2025/NĐ-CP (biện pháp thi hành Luật BV DLCN) | PEP ghi allow/deny có mục đích, principal, TTL; ledger hash-chain và DPIA-lite lưu luồng/rủi ro. | `agent/policy.py:60`, `agent/runner.py:93`, `agent/ledger.py:55`, `agent/ledger.py:73`, `reports/dpia-lite.md:1` | Không tạo hồ sơ đánh giá tác động theo biểu mẫu pháp lý, không gửi cơ quan có thẩm quyền, không có quy trình vận hành thực. |
| Luật AI 134/2025/QH15 | Phân tách run theo trust boundary, quyền tối thiểu, quyết định có truy vết và bằng chứng xử lý incident. | `agent/runner.py:130`, `agent/runner.py:185`, `agent/runner.py:193`, `agent/runner.py:219`, `reports/ledger.jsonl:1` | Mô phỏng không tự xác định hệ thống thuộc mức rủi ro pháp lý nào; chưa đánh giá vai trò chủ thể hay nghĩa vụ triển khai thực tế. |
| OWASP ASI01 Agent Goal Hijack | Free text độc hại không vượt boundary; chỉ ticket ID từ tên file đi sang Run B; egress restricted bị deny. | `agent/runner.py:130`, `agent/runner.py:185`, `agent/policy.py:64`, `reports/attack-after.log` | Detector mock không bao phủ mọi prompt injection; containment dựa trên kiến trúc và policy. |
| OWASP ASI03 Identity & Privilege Abuse | Quyền hiệu lực là giao của principal, agent scope và parent scope; kiểm purpose/TTL; OBO được ghi ledger. | `agent/policy.py:82`, `agent/policy.py:93`, `agent/runner.py:104`, `agent/runner.py:193` | `--as` chỉ chọn principal giả lập, không phải authentication/authorization production. |
| OWASP ASI04 Agentic Supply Chain Vulnerabilities | Dependency lock có hash; Gitleaks hook pin phiên bản; rule phát hiện token giả trong lịch sử. | `requirements.lock:7`, `.pre-commit-config.yaml:1`, `.gitleaks.toml:6`, `reports/secrets-incident.md:1` | Pin/hash/scanner giảm rủi ro nhưng không chứng minh artifact an toàn và không thay thế rotate credential. |

Nguồn chính thức đã đối chiếu ở mức văn bản (không suy diễn điều khoản cụ thể):

- Công báo Chính phủ — [Luật 91/2025/QH15](https://congbao.chinhphu.vn/van-ban/luat-so-91-2025-qh15-45578.htm), hiệu lực 01/01/2026.
- Cổng TTĐT Chính phủ — [Nghị định 356/2025/NĐ-CP](https://chinhphu.vn/?docid=216387&pageid=27160), hiệu lực 01/01/2026.
- Công báo Chính phủ — [Luật AI 134/2025/QH15](https://congbao.chinhphu.vn/van-ban/luat-so-134-2025-qh15-468694/61695.htm), hiệu lực 01/03/2026.
- OWASP GenAI Security Project — [Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/).

Mô phỏng kỹ thuật này không tự chứng minh tuân thủ pháp luật.
