# Tệp: math_utils.py
# Tiện ích dùng chung. Các hàm sinh khóa nằm ở keygen.py, đệm/ký/gỡ chữ ký nằm ở rsa_core.py
# (trước đây file này có bản sao của chúng, đã gỡ để mỗi hàm chỉ có MỘT nơi định nghĩa).
# Không import hashlib/hmac: lõi dùng sha256.py tự cài.


def compare_hashes(hash_A, hash_B):
    """
    Hàm so sánh hai bản băm để kiểm tra tính toàn vẹn và xác thực.
    :param hash_A: Bản băm tự tính từ tài liệu nhận được
    :param hash_B: Bản băm gỡ ra từ chữ ký số
    :return: True nếu chữ ký hợp lệ, False nếu bị giả mạo
    """
    return hash_A == hash_B and hash_B is not None
