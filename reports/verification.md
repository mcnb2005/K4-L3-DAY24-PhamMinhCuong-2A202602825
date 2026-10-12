# Verification — Phạm Minh Cương — 2A202602825

- **OS / phiên bản:** Windows NT 10.0.26200.0; Python 3.12.14;
  Gitleaks 8.30.1; pre-commit 4.6.2.
- **`python -m pytest tests/ -q -s`:** `33 passed in 7.26s`;
  PII `precision=1.000`, `recall=1.000` (118/118 true positives).
- **Lure check:** `4/4 lure sẵn sàng` cho `ticket-901` đến `ticket-904b`.
- **Dependency integrity:** `pip install --require-hashes -r requirements.lock`
  thành công; mọi package đã cài đúng phiên bản/hash lock.
- **Gitleaks history:** exit 1 như dự kiến; 4 commit được quét, đúng 1 finding
  `lab24-synthetic-token` ở commit `1bdd849`, secret được redact.
- **Gitleaks current tree:** exit 0, `no leaks found`.
- **`pre-commit run --all-files`:** `Detect hardcoded secrets — Passed`.
  Do kết nối trực tiếp tới GitHub timeout trong phiên này, pre-commit dùng
  mirror cục bộ của manifest `.pre-commit-hooks.yaml`; hook cuối cùng vẫn là
  `gitleaks-system` và gọi binary Gitleaks 8.30.1 trên các thay đổi đã stage.
- **Before/after:** `attack-before.log` 298 byte chứa POST synthetic;
  `attack-after.log` 0 byte.
- **Ledger verify:** `True`; dòng cuối là `http_post=deny`, reason
  `restricted data may not cross an egress-enabled boundary`, OBO `dpo`.
- **Lỗi còn lại:** không có lỗi code/test/scanner. Hạn chế môi trường: GitHub
  port 443 timeout nên không thể fetch hook repo trực tiếp; khi mạng ổn định,
  chạy lại `pre-commit run --all-files` không cần mirror để xác nhận đường tải.
