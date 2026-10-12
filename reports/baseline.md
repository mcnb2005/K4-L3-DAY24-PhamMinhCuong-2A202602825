# Baseline — checkpoint 1

1. **Agent chưa có identity riêng cho mỗi run.** Hàm baseline
   `agent/loop.py:_naive_loop()` (dòng 27–52) không tạo `agent_id`, `run_id`,
   principal, scope hay thời hạn uỷ quyền.
2. **Không có policy/PEP nào cho phép `http_post`.** Chính
   `agent/loop.py:_naive_loop()` gọi `tools.http_post()` ở dòng 44 ngay sau
   khi nội dung không tin cậy yêu cầu; `agent/tools.py:http_post()` chỉ giới hạn
   cứng đích tới localhost, không kiểm mục đích, principal hay phân loại dữ liệu.
3. **Bằng chứng gửi sai PII** là một POST `/reconcile` trong
   `reports/attack-before.log`. Bản ghi được tạo bởi
   `sink/sink.py:make_handler().Handler.do_POST()` (dòng 42–51) và chứa record
   synthetic của `KH-000999`.
