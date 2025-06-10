from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

def generate_key():
    return os.urandom(32)  # 256-bit key

def generate_auth_token(secret_key):
    iv = os.urandom(16)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(b"AUTHORIZED_USER", AES.block_size))
    # Base64 encode yapmadan direkt binary döndür
    return iv + ct  # IV + şifrelenmiş token

def verify_auth_token(token, secret_key):
    try:
        # Token artık binary, base64 decode etmeye gerek yok
        iv, ct = token[:16], token[16:]
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size) == b"AUTHORIZED_USER"
    except Exception as e:
        print(f"🔍 Token verify hatası: {e}")
        return False