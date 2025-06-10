from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import hashlib

def generate_key():
    """32 byte (256 bit) AES anahtarı üretir ve kaydeder."""
    key = os.urandom(32)  # 32 byte random key
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def pad(data):
    return data + b' ' * (16 - len(data) % 16)

# Orijinal encrypt_file fonksiyonu (geriye uyumluluk için)
def encrypt_file(file_path):
    key = get_random_bytes(16)  # AES-128 için 16 byte
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(file_path, "rb") as file:
        original = file.read()
    
    padded_data = pad(original)
    encrypted = cipher.encrypt(padded_data)
    
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(iv + encrypted)  # IV'yi başa ekliyoruz
    
    return encrypted_file_path, key  # Anahtarı da dönüyoruz

# Orijinal decrypt_file fonksiyonu (geriye uyumluluk için)
def decrypt_file(encrypted_file_path, key, output_file_path=None):
    """
    Şifrelenmiş dosyayı çözer
    Args:
        encrypted_file_path: Şifrelenmiş dosya yolu
        key: Şifreleme anahtarı
        output_file_path: Çıktı dosya yolu (opsiyonel)
    """
    if output_file_path is None:
        output_file_path = "decrypted_file.txt"
    
    try:
        with open(encrypted_file_path, "rb") as file:
            iv = file.read(16)
            encrypted_data = file.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = decrypted_padded.rstrip(b' ')
        
        with open(output_file_path, "wb") as file:
            file.write(decrypted)
        
        print(f"{encrypted_file_path} başarıyla çözüldü → {output_file_path}")
        return output_file_path
    except Exception as e:
        print(f"❌ Deşifreleme hatası: {e}")
        return "DECRYPT_FAILED"

# ===================== YENİ ÖZELLIKLER (PROJE GEREKSİNIMLERİ) =====================

def generate_rsa_keys():
    """RSA anahtar çifti oluşturur (Proje gereksinimi: RSA encryption)"""
    try:
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        # Anahtar dosyalarını kaydet
        with open("private.pem", "wb") as f:
            f.write(private_key)
        with open("public.pem", "wb") as f:
            f.write(public_key)
        
        print("🔑 RSA anahtar çifti oluşturuldu (private.pem, public.pem)")
        return private_key, public_key
    except Exception as e:
        print(f"❌ RSA anahtar oluşturma hatası: {e}")
        return None, None

def encrypt_aes_key_with_rsa(aes_key, public_key_path="public.pem"):
    """AES anahtarını RSA ile şifreler (Hibrit şifreleme)"""
    try:
        if not os.path.exists(public_key_path):
            print("⚠️ RSA public key bulunamadı, oluşturuluyor...")
            generate_rsa_keys()
        
        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        return encrypted_aes_key
    except Exception as e:
        print(f"❌ RSA şifreleme hatası: {e}")
        return None

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_path="private.pem"):
    """RSA ile şifrelenmiş AES anahtarını çözer"""
    try:
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())
        
        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        return aes_key
    except Exception as e:
        print(f"❌ RSA deşifreleme hatası: {e}")
        return None

def calculate_file_hash(file_path):
    """Dosyanın SHA-256 hash'ini hesaplar (Proje gereksinimi: Integrity validation)"""
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"❌ Hash hesaplama hatası: {e}")
        return None

def verify_file_integrity(file_path, expected_hash):
    """Dosya bütünlüğünü doğrular (SHA-256 ile)"""
    actual_hash = calculate_file_hash(file_path)
    if actual_hash:
        return actual_hash == expected_hash
    return False

def encrypt_file_hybrid(file_path):
    """
    Hibrit şifreleme: AES + RSA (Proje Ana Gereksinimi)
    - Dosyayı AES ile şifreler
    - AES anahtarını RSA ile şifreler
    - SHA-256 ile integrity kontrolü sağlar
    """
    try:
        print(f"🔒 Hibrit şifreleme başlatılıyor: {file_path}")
        
        # 1. RSA anahtar çifti kontrolü
        if not os.path.exists("public.pem") or not os.path.exists("private.pem"):
            print("🔑 RSA anahtarları oluşturuluyor...")
            generate_rsa_keys()
        
        # 2. Dosya hash'ini hesapla (integrity için)
        original_hash = calculate_file_hash(file_path)
        print(f"📋 Orijinal dosya hash'i: {original_hash}")
        
        # 3. AES ile dosyayı şifrele (256-bit AES)
        aes_key = get_random_bytes(32)  # 256-bit AES key
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        with open(file_path, "rb") as f:
            original_data = f.read()
        
        padded_data = pad(original_data)
        encrypted_data = cipher.encrypt(padded_data)
        
        # 4. AES anahtarını RSA ile şifrele
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key)
        if not encrypted_aes_key:
            return None, None, None
        
        # 5. Hibrit şifrelenmiş dosyayı oluştur
        encrypted_file_path = file_path + ".hybrid_encrypted"
        with open(encrypted_file_path, "wb") as f:
            # Dosya formatı: [RSA_KEY_LEN][ENCRYPTED_AES_KEY][HASH_LEN][FILE_HASH][IV][ENCRYPTED_DATA]
            f.write(len(encrypted_aes_key).to_bytes(4, 'big'))  # RSA encrypted key length
            f.write(encrypted_aes_key)  # RSA ile şifrelenmiş AES anahtarı
            f.write(len(original_hash.encode()).to_bytes(4, 'big'))  # Hash length
            f.write(original_hash.encode())  # Orijinal dosya hash'i
            f.write(iv)  # AES IV
            f.write(encrypted_data)  # AES ile şifrelenmiş veri
        
        print(f"✅ Hibrit şifreleme tamamlandı: {encrypted_file_path}")
        return encrypted_file_path, aes_key, original_hash
        
    except Exception as e:
        print(f"❌ Hibrit şifreleme hatası: {e}")
        return None, None, None

def decrypt_file_hybrid(encrypted_file_path, output_file_path="decrypted_hybrid_file.txt"):
    """
    Hibrit şifrelenmiş dosyayı çözer ve integrity kontrolü yapar
    """
    try:
        print(f"🔓 Hibrit deşifreleme başlatılıyor: {encrypted_file_path}")
        
        with open(encrypted_file_path, "rb") as f:
            # RSA encrypted AES key'i oku
            rsa_key_len = int.from_bytes(f.read(4), 'big')
            encrypted_aes_key = f.read(rsa_key_len)
            
            # Hash bilgisini oku
            hash_len = int.from_bytes(f.read(4), 'big')
            expected_hash = f.read(hash_len).decode()
            
            # IV ve encrypted data'yı oku
            iv = f.read(16)
            encrypted_data = f.read()
        
        # AES anahtarını RSA ile çöz
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key)
        if not aes_key:
            return None
        
        # AES ile veriyi çöz
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = decrypted_padded.rstrip(b' ')
        
        # Çözülen dosyayı kaydet
        with open(output_file_path, "wb") as f:
            f.write(decrypted_data)
        
        # Integrity kontrolü
        actual_hash = calculate_file_hash(output_file_path)
        if verify_file_integrity(output_file_path, expected_hash):
            print(f"✅ Hibrit deşifreleme ve integrity kontrolü başarılı: {output_file_path}")
            print(f"🔍 Hash doğrulaması: ✓ Geçti")
        else:
            print(f"⚠️ Integrity kontrolü başarısız!")
            print(f"🔍 Beklenen hash: {expected_hash}")
            print(f"🔍 Gerçek hash: {actual_hash}")
        
        return output_file_path
        
    except Exception as e:
        print(f"❌ Hibrit deşifreleme hatası: {e}")
        return None

# ===================== TEST FONKSİYONU =====================

def test_encryption_methods():
    """Şifreleme yöntemlerini test eder"""
    print("\n" + "="*50)
    print("🧪 ŞİFRELEME YÖNTEMLERİ TESTİ")
    print("="*50)
    
    # Test dosyası oluştur
    test_file = "test_encryption.txt"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("Bu bir test dosyasıdır.\nHibrit şifreleme testi.\nAES + RSA kombinasyonu.")
    
    # 1. Orijinal AES testi
    print("\n1️⃣ Orijinal AES Şifreleme Testi:")
    enc_file, key = encrypt_file(test_file)
    if enc_file:
        decrypt_file(enc_file, key, "test_aes_decrypted.txt")
    
    # 2. Hibrit şifreleme testi
    print("\n2️⃣ Hibrit AES+RSA Şifreleme Testi:")
    hybrid_enc, aes_key, file_hash = encrypt_file_hybrid(test_file)
    if hybrid_enc:
        decrypt_file_hybrid(hybrid_enc, "test_hybrid_decrypted.txt")
    
    print("\n✅ Test tamamlandı!")

if __name__ == "__main__":
    test_encryption_methods()