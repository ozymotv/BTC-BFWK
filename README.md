# PLUTUS BITCOIN BRUTE FORCER - FIXED VERSION
## For education purposes only

### CÁC LỖI ĐÃ SỬA

1. ✓ **Lỗi typo trong tên folder** (QUAN TRỌNG)
   - Trước: `DATABASE = r'database/lastest/'`
   - Sau: `DATABASE = r'database/latest/'`

2. ✓ **Loại bỏ redundant variable**
   - Trước: `alphabet = chars = '123...'`
   - Sau: Chỉ dùng `alphabet`

3. ✓ **Đảm bảo UTF-8 encoding**
   - File đã được lưu với UTF-8 encoding

### YÊU CẦU HỆ THỐNG

**Dependencies bắt buộc:**
```bash
pip install fastecdsa
pip install ellipticcurve
```

**Dependencies tùy chọn (khuyến nghị):**
```bash
pip install psutil  # Cho CPU limiting tốt hơn
```

**Cấu trúc thư mục:**
```
.
├── plutus_cpu_limited_fixed.py
├── database/
│   └── latest/              # <-- Tên folder đúng
│       ├── file1.txt
│       ├── file2.txt
│       └── ...
└── plutus_seed.txt          # Tự động tạo khi chạy
```

### CÁCH SỬ DỤNG

**1. Cài đặt dependencies:**
```bash
pip install fastecdsa ellipticcurve psutil
```

**2. Tạo thư mục database:**
```bash
mkdir -p database/latest
```

**3. Thêm địa chỉ Bitcoin vào database:**
Tạo file `.txt` trong `database/latest/` với mỗi dòng là 1 địa chỉ Bitcoin:
```
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
...
```

**4. Test script:**
```bash
python3 plutus_cpu_limited_fixed.py time
```

**5. Chạy script:**

Mặc định (80% CPU):
```bash
python3 plutus_cpu_limited_fixed.py
```

Chạy với 30% CPU:
```bash
python3 plutus_cpu_limited_fixed.py cpu_limit=30
```

Chạy 2 processes, mỗi process 50% CPU:
```bash
python3 plutus_cpu_limited_fixed.py cpu_count=2 cpu_limit=50
```

Background mode (20% CPU, low priority):
```bash
python3 plutus_cpu_limited_fixed.py cpu_limit=20 priority=low
```

Verbose mode (hiển thị addresses):
```bash
python3 plutus_cpu_limited_fixed.py verbose=1
```

### CÁC THAM SỐ

| Tham số | Giá trị | Mặc định | Mô tả |
|---------|---------|----------|-------|
| `cpu_limit` | 1-100 | 80 | % CPU mỗi process sử dụng |
| `cpu_count` | 1-N | All cores | Số process chạy song song |
| `priority` | low/below_normal/normal | below_normal | Mức ưu tiên process |
| `verbose` | 0/1 | 0 | Hiển thị địa chỉ đang kiểm tra |
| `substring` | 1-26 | 8 | Số ký tự cuối so khớp |
| `reset_seed` | - | - | Xóa seed cũ và tạo seed mới |

### VÍ DỤ SỬ DỤNG THỰC TẾ

**Chạy ngầm trên server (không làm chậm server):**
```bash
python3 plutus_cpu_limited_fixed.py cpu_limit=15 cpu_count=2 priority=low
```
→ Chỉ dùng ~30% CPU tổng

**Chạy trên máy cá nhân khi đang làm việc:**
```bash
python3 plutus_cpu_limited_fixed.py cpu_limit=40 cpu_count=4
```
→ Dùng ~160% CPU (1.6 cores), còn lại cho công việc khác

**Chạy full speed khi không dùng máy:**
```bash
python3 plutus_cpu_limited_fixed.py cpu_limit=100
```
→ Sử dụng 100% tất cả cores

### XỬ LÝ LỖI

**Lỗi: "Database not found"**
```bash
# Kiểm tra thư mục có đúng không
ls -la database/latest/

# Nếu không có, tạo thư mục
mkdir -p database/latest
```

**Lỗi: "No module named 'fastecdsa'"**
```bash
pip install fastecdsa ellipticcurve
```

**Lỗi encoding khi chạy:**
```bash
# Đảm bảo terminal hỗ trợ UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Hoặc chạy với Python UTF-8 mode
PYTHONUTF8=1 python3 plutus_cpu_limited_fixed.py
```

**Lỗi "Cannot set high priority":**
- Bình thường, không ảnh hưởng
- Để set high priority trên Linux/Mac cần chạy với sudo
- Không khuyến khích dùng high priority

### KẾT QUẢ KHI TÌM THẤY

Khi tìm thấy địa chỉ match, script sẽ:
1. Lưu vào file `plutus.txt`
2. Tạo backup `plutus_backup_[timestamp].txt`
3. Tạo file riêng `found_key_[counter]_[process].txt`
4. In ra console để copy (nếu không save được)

### DỪNG CHƯƠNG TRÌNH

**Dừng an toàn:**
```bash
Ctrl + C
```
→ Script sẽ lưu progress trước khi thoát

**Progress được lưu trong:**
- `plutus_seed.txt` - Seed và counter hiện tại
- Tự động save mỗi 1000 keys

### LƯU Ý BẢO MẬT

⚠️ **QUAN TRỌNG:**
- `plutus_seed.txt` chứa seed để generate keys
- Backup file này thường xuyên
- KHÔNG share seed này với ai
- Nếu tìm thấy key có tiền, transfer ngay

### TÍNH TOÁN THỜI GIAN

Script cho phép tính toán thời gian ước tính:
```bash
python3 plutus_cpu_limited_fixed.py time
```

Sẽ hiển thị:
- Tốc độ keys/giây
- Thời gian để scan hết 2^160 địa chỉ
- Sample address để verify

### HỖ TRỢ

Nếu gặp lỗi không nằm trong danh sách trên:
1. Chạy lệnh `time` để test
2. Kiểm tra Python version: `python3 --version` (cần >= 3.6)
3. Kiểm tra cài đặt: `pip list | grep -E "fastecdsa|ellipticcurve|psutil"`
4. Kiểm tra quyền: `ls -la database/latest/`

---

**Phiên bản:** Fixed v1.0
**Ngày cập nhật:** 05/10/2025
**Đã sửa lỗi typo 'lastest' → 'latest'**
