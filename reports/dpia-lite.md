# DPIA-lite — checkpoint 5

1. **Loại dữ liệu và phân loại.** Fixture chỉ chứa dữ liệu synthetic: mã khách
   hàng, họ tên, CCCD, số điện thoại, số tài khoản, email và ticket liên quan.
   Hồ sơ khách hàng được gắn `restricted`; corpus/ticket là nội dung `internal`
   nhưng không tin cậy. Không dùng dữ liệu cá nhân hay credential thật.
2. **Mục đích và principal.** `summarize-tickets` cho Run A và
   `support-reply` cho Run B. Principal mô phỏng `support_l1` chỉ được
   `search_docs`; `dpo` được `read_customer` khi tool nằm trong cả agent scope
   và parent scope, mục đích hợp lệ, uỷ quyền chưa hết hạn.
3. **Luồng dữ liệu.** Run A gọi `search_docs`, phát hiện injection nhưng chỉ
   truyền `list[int]` ticket ID lấy từ tên file sang Run B. Run B tra mapping
   ticket→customer từ `data/customers.json`, rồi PEP kiểm ngay trước
   `read_customer`. Nội dung corpus được redact trước khi summarize. Payload
   độc hại yêu cầu POST tới duy nhất `http://127.0.0.1:10024/reconcile`; PEP
   chặn `restricted + egress`, nên không có record nào tới sink.
4. **Bằng chứng và rủi ro còn lại.** `reports/attack-before.log` chứng minh
   baseline từng gửi record synthetic; `reports/attack-after.log` rỗng;
   `reports/ledger.jsonl` ghi cả allow lẫn deny, reason, OBO, TTL và hash-chain.
   Đây chỉ là mock localhost: `--as` không xác thực người dùng, registry JSON
   không phải IAM, ledger không có external anchor và có thể bị viết lại/xoá
   đuôi bởi đối thủ có toàn quyền, regex PII/detector không bao phủ mọi biến
   thể, chưa có retention/deletion/DSAR/incident workflow production.
