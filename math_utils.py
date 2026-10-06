import random
import hashlib

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
    # Hàm hỗ trợ tìm nghịch đảo modulo bên trong
    def extended_gcd(a, b):
        if a == 0: return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        return gcd, y1 - (b // a) * x1, x1

    def mod_inverse(e, phi):
        gcd, x, y = extended_gcd(e, phi)
        if gcd != 1: raise ValueError("Không có nghịch đảo modulo")
        return x % phi
        
    def is_prime(n):
        if n <= 1: return False
        if n <= 3: return True
        if n % 2 == 0: return False
        # Miller-Rabin đơn giản
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(5):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1: continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else: return False
        return True

    # Nếu không truyền p, q thì tự sinh số nguyên tố ngẫu nhiên
    if p is None or q is None:
        if keysize is None:
            raise ValueError("Phải truyền p, q hoặc keysize")
        bits = keysize // 2
        while True:
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if is_prime(p): break
        while True:
            q = random.getrandbits(bits) | (1 << bits - 1) | 1
            if is_prime(q) and p != q: break

    N = p * q
    phi = (p - 1) * (q - 1)
    
    # Chọn e
    e = 65537
    def gcd_func(a, b):
        while b: a, b = b, a % b
        return a
        
    if gcd_func(e, phi) != 1:
        e = 3
        while gcd_func(e, phi) != 1: e += 2

    # Tính d
    d = mod_inverse(e, phi)
    
    return (d, N), (e, N)

# --- Định dạng cho sha256.py ---
def hash_sha256(message):
    """
    Hàm băm thông điệp sử dụng SHA-256.
    :param message: Tài liệu gốc (khi ký) hoặc Tài liệu nhận được (khi xác thực)
    :return: Dữ liệu đã được băm (chuỗi hex)
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    # Có thể dùng hashlib cho gọn, hoặc gọi lại code SHA-256 tự viết của bạn
    return hashlib.sha256(message).hexdigest()

# --- Định dạng cho padding.py ---
def add_pkcs1_v15_padding(hash_value, em_length):
    """
    Hàm thêm đệm PKCS#1 v1.5 vào giá trị băm trước khi ký.
    :param hash_value: Giá trị băm SHA-256 (chuỗi hex)
    :param em_length: Độ dài của thông điệp mã hóa (tính bằng byte, = keysize // 8)
    :return: Dữ liệu đã được thêm đệm dạng số nguyên
    """
    hash_bytes = bytes.fromhex(hash_value)
    # Prefix định danh chuẩn của SHA-256 trong PKCS#1 v1.5
    prefix = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    t = prefix + hash_bytes
    
    if em_length < len(t) + 11:
        raise ValueError("Độ dài khóa quá ngắn để đệm (cần ít nhất 1024-bit)")
        
    ps = b'\xff' * (em_length - len(t) - 3)
    padded_msg = b'\x00\x01' + ps + b'\x00' + t
    
    return int.from_bytes(padded_msg, 'big')

def verify_signature(signature, public_key):
    """
    Hàm gỡ chữ ký số để lấy bản băm (Bản băm B).
    :param signature: Chữ ký số S từ người gửi (dạng số nguyên)
    :param public_key: Khóa công khai (e, N)
    :return: Bản băm B sau khi dùng khóa công khai để giải mã
    """
    e, N = public_key
    # Giải mã bằng hàm pow tích hợp (tương đương mod_exp)
    padded_hash_int = pow(signature, e, N)
    
    # Chuyển số nguyên về lại dạng byte
    em_length = (N.bit_length() + 7) // 8
    padded_msg = padded_hash_int.to_bytes(em_length, 'big')
    
    # Cắt bỏ phần đệm để trích xuất mã băm
    try:
        # Tìm vị trí byte 0x00 kết thúc chuỗi đệm FF
        zero_idx = padded_msg.index(b'\x00', 2)
        # Bỏ qua phần đệm và 19 byte prefix của SHA-256
        hash_bytes = padded_msg[zero_idx + 1 + 19:]
        return hash_bytes.hex()
    except ValueError:
        return None

def compare_hashes(hash_A, hash_B):
    """
    Hàm so sánh hai bản băm để kiểm tra tính toàn vẹn và xác thực.
    :param hash_A: Bản băm tự tính từ tài liệu nhận được
    :param hash_B: Bản băm gỡ ra từ chữ ký số
    :return: True nếu chữ ký hợp lệ, False nếu bị giả mạo
    """
    return hash_A == hash_B and hash_B is not None
