# --- Định dạng cho rsa_math.py / keygen.py ---
def generate_key_pair(keysize):
    """
    Hàm tạo cặp khóa RSA.
    :param keysize: Độ dài của khóa (ví dụ: 1024, 2048)
    :return: Khóa riêng (d, N) và Khóa công khai (e, N)
    """
    pass

# --- Định dạng cho sha256.py ---
def hash_sha256(message):
    """
    Hàm băm thông điệp sử dụng SHA-256.
    :param message: Tài liệu gốc (khi ký) hoặc Tài liệu nhận được (khi xác thực)
    :return: Dữ liệu đã được băm
    """
    pass

# --- Định dạng cho padding.py ---
def add_pkcs1_v15_padding(hash_value, em_length):
    """
    Hàm thêm đệm PKCS#1 v1.5 vào giá trị băm trước khi ký.
    :param hash_value: Giá trị băm SHA-256
    :param em_length: Độ dài của thông điệp mã hóa
    :return: Dữ liệu đã được thêm đệm
    """
    pass

# --- Định dạng cho rsa_math.py / keygen.py ---
def generate_key_pair(p=None, q=None, keysize=None):
    """
    Hàm tạo cặp khóa RSA. 
    Nếu dùng ví dụ trên lớp (số nhỏ), hãy truyền p và q vào.
    Nếu chạy thực tế, chỉ cần truyền keysize để hệ thống tự sinh số lớn.
    
    :param p: Số nguyên tố thứ nhất (tùy chọn, dùng cho ví dụ tính tay)
    :param q: Số nguyên tố thứ hai (tùy chọn, dùng cho ví dụ tính tay)
    :param keysize: Độ dài của khóa ngẫu nhiên (ví dụ: 1024, 2048)
    :return: Khóa riêng (d, N) và Khóa công khai (e, N)
    """
    pass

def verify_signature(signature, public_key):
    """
    Hàm gỡ chữ ký số để lấy bản băm (Bản băm B).
    :param signature: Chữ ký số S từ người gửi
    :param public_key: Khóa công khai (e, N)
    :return: Bản băm B sau khi dùng khóa công khai để giải mã
    """
    pass

def compare_hashes(hash_A, hash_B):
    """
    Hàm so sánh hai bản băm để kiểm tra tính toàn vẹn và xác thực.
    :param hash_A: Bản băm tự tính từ tài liệu nhận được
    :param hash_B: Bản băm gỡ ra từ chữ ký số
    :return: True nếu chữ ký hợp lệ, False nếu bị giả mạo
    """
    pass
