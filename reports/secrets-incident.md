# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1, cấu hình custom
  `.gitleaks.toml`; hook `gitleaks-system` được pin cùng phiên bản.
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c`
  (short SHA `1bdd849`). File `lab-fake-secret.txt`, token cố ý vô hiệu có
  prefix `LAB24-DEMO`; file được xoá ở commit `ece6ca4`.
- **Rule và quét lịch sử:** rule `lab24-synthetic-token`. Lệnh
  `gitleaks git --config .gitleaks.toml --redact --verbose .` trả exit code 1,
  quét 4 commit và báo đúng **1 finding** tại commit `1bdd849`, dòng 1 của
  `lab-fake-secret.txt`. Đây là dữ liệu cài sẵn cho bài lab, không phải sự cố
  credential thật.
- **Quét file hiện tại:** `gitleaks dir --config .gitleaks.toml .` trả exit
  code 0 và `no leaks found`; file token giả đã bị xoá khỏi HEAD.
- **Nếu đây là credential thật:** thu hồi/rotate ngay tại nhà cung cấp trước,
  xác định phạm vi lộ và log sử dụng, cập nhật mọi consumer, thông báo theo
  quy trình incident, giám sát hành vi bất thường; sau đó mới cân nhắc purge
  lịch sử Git và phối hợp người đã clone/fork.
- **Vì sao xoá hoặc pin chưa đủ:** xoá khỏi HEAD không làm credential cũ mất
  hiệu lực và bản sao vẫn tồn tại trong lịch sử/clone. Pin dependency/hook chỉ
  giảm thay đổi supply-chain, không thu hồi quyền đã cấp cho secret bị lộ.
