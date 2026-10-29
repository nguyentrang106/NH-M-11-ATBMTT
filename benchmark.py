# Tệp: benchmark.py
# Đo tốc độ: SHA-256 tự cài vs hashlib, sinh khóa, ký, xác thực, HMAC.
import hashlib
import hmac as std_hmac
import os
import statistics
import sys
import time

from sha256 import hash_sha256
from keygen import generate_keypair
from rsa_core import sign_message, verify_message
import hmac_utils


def _time(fn, repeat):
    """Chạy fn() 'repeat' lần, trả về (trung bình, nhỏ nhất) tính bằng mili-giây."""
    samples = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(samples), min(samples)


def run_benchmark(real=False, verbose=True):
    """
    :param real: False -> khóa 512/1024 bit (nhanh); True -> 1024/2048 bit (thực tế)
    :return: dict kết quả
    """
    say = print if verbose else (lambda *a, **k: None)
    sizes = (1024, 2048) if real else (512, 1024)
    results = {}

    say("=" * 70)
    say(f" BENCHMARK ({'REAL: khóa 1024/2048 bit' if real else 'NHANH: khóa 512/1024 bit'})")
    say("=" * 70)

    # --- Băm ---
    say("\n[1] Hàm băm SHA-256 (ms / lần)")
    say(f"    {'Kích thước':<14}{'Tự cài (sha256.py)':>22}{'hashlib':>12}{'Chậm hơn':>12}")
    for label, n in (("64 B", 64), ("10 KB", 10_000), ("100 KB", 100_000)):
        data = os.urandom(n)
        assert hash_sha256(data) == hashlib.sha256(data).hexdigest()
        mine, _ = _time(lambda: hash_sha256(data), 3 if n > 10_000 else 10)
        lib, _ = _time(lambda: hashlib.sha256(data).hexdigest(), 50)
        results[f"sha256_{label}"] = (mine, lib)
        say(f"    {label:<14}{mine:>22.3f}{lib:>12.4f}{mine / max(lib, 1e-9):>11.0f}x")

    # --- HMAC ---
    say("\n[2] HMAC-SHA256 (ms / lần, thông điệp 1 KB)")
    key, msg = b"khoa-bi-mat", os.urandom(1024)
    assert hmac_utils.generate_hmac(key, msg) == std_hmac.new(key, msg, hashlib.sha256).hexdigest()
    mine, _ = _time(lambda: hmac_utils.generate_hmac(key, msg), 10)
    lib, _ = _time(lambda: std_hmac.new(key, msg, hashlib.sha256).hexdigest(), 50)
    results["hmac"] = (mine, lib)
    say(f"    Tự cài: {mine:.3f} ms | thư viện chuẩn: {lib:.4f} ms")

    # --- RSA ---
    say("\n[3] RSA: sinh khóa, ký, xác thực (ms / lần)")
    say(f"    {'Khóa (bit)':<12}{'Sinh khóa (TB)':>16}{'Ký':>12}{'Xác thực':>12}{'Ký/Xác thực':>14}")
    doc = "Hop dong mua ban so 01/2026"
    for bits in sizes:
        holder = {}

        def gen():
            holder["k"] = generate_keypair(keysize=bits)

        g_mean, _ = _time(gen, 5 if bits <= 1024 else 3)
        priv, pub = holder["k"]
        sig = sign_message(doc, priv)
        assert verify_message(doc, sig, pub)
        s_mean, _ = _time(lambda: sign_message(doc, priv), 20)
        v_mean, _ = _time(lambda: verify_message(doc, sig, pub), 200)
        results[f"rsa_{bits}"] = (g_mean, s_mean, v_mean)
        say(f"    {bits:<12}{g_mean:>16.1f}{s_mean:>12.3f}{v_mean:>12.3f}{s_mean / v_mean:>13.0f}x")

    # --- Thời gian ký / kiểm tra theo kích thước dữ liệu ---
    bits = sizes[-1]
    priv, pub = generate_keypair(keysize=bits)
    say(f"\n[4] Thời gian ký và kiểm tra theo kích thước dữ liệu (khóa {bits} bit, ms / lần)")
    say(f"    {'Dữ liệu':<12}{'Ký':>12}{'Kiểm tra':>12}{'Phần băm chiếm':>18}")
    for label, n in (("1 KB", 1_000), ("10 KB", 10_000), ("100 KB", 100_000)):
        data = os.urandom(n)
        sig = sign_message(data, priv)
        assert verify_message(data, sig, pub)
        rep = 3 if n >= 100_000 else 10
        t_sign, _ = _time(lambda: sign_message(data, priv), rep)
        t_ver, _ = _time(lambda: verify_message(data, sig, pub), rep)
        t_hash, _ = _time(lambda: hash_sha256(data), rep)
        results[f"file_{label}"] = (t_sign, t_ver)
        say(f"    {label:<12}{t_sign:>12.2f}{t_ver:>12.2f}{100 * t_hash / t_sign:>17.0f}%")

    say("\nNhận xét: ký (dùng d lớn) chậm hơn xác thực (dùng e = 65537 nhỏ) nhiều lần;")
    say("thời gian sinh khóa dao động mạnh vì phải thử ngẫu nhiên tìm số nguyên tố.")
    say("Với tệp lớn, thời gian ký/kiểm tra gần như chỉ là thời gian băm: RSA chỉ ký 1 lần trên bản băm 32 byte.")
    return results


if __name__ == "__main__":
    run_benchmark(real="--real" in sys.argv)
