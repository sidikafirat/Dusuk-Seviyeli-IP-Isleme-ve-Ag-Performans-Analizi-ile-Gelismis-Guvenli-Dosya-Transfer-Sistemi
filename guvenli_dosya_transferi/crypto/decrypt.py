from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_file(encrypted_file_path, output_file_path, key):
    try:
        # Şifrelenmiş dosyayı oku
        with open(encrypted_file_path, "rb") as file:
            data = file.read()
            
            # İlk 16 byte IV, geri kalanı şifrelenmiş veri
            iv = data[:16]
            ciphertext = data[16:]
            
            # IV boyut kontrolü
            if len(iv) != 16:
                raise ValueError(f"Incorrect IV length: {len(iv)} bytes (must be 16)")
            
            # Şifre çözme işlemi
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            # Çözülmüş dosyayı yaz
            with open(output_file_path, "wb") as file:
                file.write(decrypted)
                
            print(f"✅ Dosya başarıyla çözüldü: {output_file_path}")
            
    except Exception as e:
        print(f"❌ Şifre çözme hatası: {type(e).__name__}: {str(e)}")
        raise