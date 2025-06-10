import os
import socket
import hashlib
import time  
import struct
import random
from crypto.encrypt import encrypt_file
from utils.logger import log_info, log_error, log_warning
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode
from crypto.key_generator import generate_auth_token
from scapy.all import IP, TCP, UDP, send, Raw
import logging 
from network.performance import measure_bandwidth
from crypto.key_generator import generate_key
from metrics_manager import MetricsManager
import threading

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001
UDP_PORT = 5002  # Wireshark analizi için UDP port

class WiresharkAnalyzer:
    """Wireshark analizi için paket gönderme ve izleme sınıfı"""
    
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self.packet_id = random.randint(1000, 9999)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    def send_marker_packet(self, marker_type, data=""):
        """Wireshark'ta ayırt edilebilir marker paketleri gönder"""
        try:
            timestamp = int(time.time() * 1000)  # Milliseconds
            marker_data = f"MARKER_{marker_type}_{timestamp}_{data}"
            
            # UDP marker paketi gönder (bu çalışıyor)
            self.udp_socket.sendto(
                marker_data.encode('utf-8'), 
                (self.target_ip, UDP_PORT)
            )
            print(f"📊 UDP Marker: {marker_type} - {data}")
            
            # Scapy yerine ham socket kullan (daha güvenilir)
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                # Ham socket gerektiriyor, bu yüzden sadece UDP kullanacağız
            except (PermissionError, OSError):
                # Yönetici izni gerekiyor, sadece UDP kullan
                pass
            
            self.packet_id += 1
            
        except Exception as e:
            print(f"⚠️ Marker paketi gönderilemedi: {e}")
    
    def send_test_patterns(self):
        """Wireshark analizi için test paketleri gönder"""
        print("🔍 Wireshark test paketleri gönderiliyor...")
        
        # 1. Başlangıç marker
        self.send_marker_packet("START", "FILE_TRANSFER_BEGIN")
        time.sleep(0.1)
        
        # 2. Farklı boyutlarda UDP paketleri
        sizes = [64, 128, 256, 512, 1024]
        for size in sizes:
            test_data = "X" * (size - 50)  # Header için yer bırak
            packet_info = f"SIZE_TEST_{size}_BYTES"
            self.udp_socket.sendto(
                f"{packet_info}_{test_data}".encode('utf-8'), 
                (self.target_ip, UDP_PORT)
            )
            print(f"📦 Test paketi gönderildi: {size} bytes")
            time.sleep(0.05)
        
        # 3. Fragmented IP paketleri
        self.send_fragmented_test()
        
        # 4. TTL testi
        self.send_ttl_test()
        
        time.sleep(0.1)
        self.send_marker_packet("TESTS_COMPLETE", "READY_FOR_TRANSFER")
    
    def send_fragmented_test(self):
        """IP fragmentasyon testi - UDP ile güvenli versiyon"""
        try:
            large_data = "FRAGMENT_TEST_" + "A" * 500  # Daha küçük parçalar
            chunk_size = 100
            
            for i in range(0, len(large_data), chunk_size):
                chunk = large_data[i:i+chunk_size]
                fragment_info = f"FRAG_{i//chunk_size}_OF_{len(large_data)//chunk_size}"
                
                # UDP ile fragment simülasyonu
                self.udp_socket.sendto(
                    f"{fragment_info}_{chunk}".encode('utf-8'),
                    (self.target_ip, UDP_PORT)
                )
                print(f"🧩 UDP Fragment gönderildi: part={i//chunk_size}, size={len(chunk)}")
                time.sleep(0.01)
                
        except Exception as e:
            print(f"⚠️ Fragment testi hatası: {e}")
    
    def send_ttl_test(self):
        """TTL değerleri ile test paketleri - UDP versiyon"""
        ttl_values = [32, 64, 128, 255]
        for ttl in ttl_values:
            try:
                # UDP ile TTL simülasyonu
                ttl_data = f"TTL_TEST_{ttl}_SIMULATION"
                self.udp_socket.sendto(
                    ttl_data.encode('utf-8'),
                    (self.target_ip, UDP_PORT)
                )
                print(f"⏱️ UDP TTL test paketi: {ttl}")
                time.sleep(0.01)
            except Exception as e:
                print(f"⚠️ TTL test hatası: {e}")
    
    def monitor_transfer_progress(self, chunk_count, chunk_index):
        """Transfer ilerlemesini Wireshark'ta işaretle"""
        if chunk_index % 10 == 0 or chunk_index == chunk_count - 1:
            progress = (chunk_index / chunk_count) * 100
            self.send_marker_packet("PROGRESS", f"{progress:.1f}%_CHUNK_{chunk_index}")
    
    def close(self):
        """Kaynakları temizle"""
        try:
            self.udp_socket.close()
        except:
            pass

def send_udp_heartbeat():
    """Arka planda UDP heartbeat paketleri gönder"""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    count = 0
    
    try:
        while True:
            heartbeat_msg = f"HEARTBEAT_{count}_{time.strftime('%H:%M:%S')}"
            udp_sock.sendto(heartbeat_msg.encode(), (SERVER_HOST, UDP_PORT))
            print(f"💓 Heartbeat #{count}")
            count += 1
            time.sleep(3)
    except Exception as e:
        print(f"Heartbeat hatası: {e}")
    finally:
        udp_sock.close()

# Dosyayı parçalarına ayırma
def split_file(file_path, chunk_size=1024):
    with open(file_path, "rb") as file:
        file_data = file.read()
    
    chunks = []
    for i in range(0, len(file_data), chunk_size):
        chunk = file_data[i:i+chunk_size]
        chunks.append(chunk)
    
    return chunks

# Checksum hesaplama (SHA-256)
def calculate_checksum(data):
    checksum = hashlib.sha256(data).hexdigest()
    return checksum

def calculate_ip_checksum(ip_header):
    total = 0
    for i in range(0, 20, 2):  # IP başlığı 20 byte
        word = (ip_header[i] << 8) + ip_header[i+1]
        total += word
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff

# Şifreli token oluşturma
def generate_auth_token(secret_key: bytes, token_message: str = "AUTHORIZED_USER") -> bytes:
    cipher = AES.new(secret_key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(token_message.encode(), AES.block_size))
    return cipher.iv + ct

def recv_all(sock, length):
    data = b""
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise EOFError("Bağlantı kapandı veya veri eksik")
        data += more
    return data

def start_sender():
    print("🚀 Gönderici başlatılıyor...")
    print("🔍 Wireshark analizi aktif!")
    
    # Wireshark analyzer başlat
    analyzer = WiresharkAnalyzer(SERVER_HOST)
    
    # Heartbeat thread başlat
    heartbeat_thread = threading.Thread(target=send_udp_heartbeat, daemon=True)
    heartbeat_thread.start()
    
    # Değişkenleri başta tanımla
    start_time = time.time()
    packet_count = 0
    file_size = 0
    file_path = "test_files/ornek.txt"
    
    try:
        # Wireshark test paketleri gönder
        analyzer.send_test_patterns()
        time.sleep(1)
        
        # Ana transfer başlangıcını işaretle
        analyzer.send_marker_packet("MAIN_TRANSFER", "TCP_CONNECTION_START")
        
        s = socket.socket()
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"🔌 Bağlantı kuruldu: {SERVER_HOST}:{SERVER_PORT}")
        
        # Bağlantı kuruldu marker
        analyzer.send_marker_packet("TCP_CONNECTED", f"PORT_{SERVER_PORT}")

        # Dosya var mı kontrol et
        if not os.path.exists(file_path):
            print(f"❌ Dosya bulunamadı: {file_path}")
            print("📁 test_files klasörü ve ornek.txt dosyası oluşturuluyor...")
            os.makedirs("test_files", exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("Bu bir test dosyasıdır.\nGüvenli dosya transferi testi.\nWireshark analizi için hazırlanmıştır.\n" * 10)
            print(f"✅ Test dosyası oluşturuldu: {file_path}")
        
        # Dosya boyutunu al
        file_size = os.path.getsize(file_path)
        analyzer.send_marker_packet("FILE_INFO", f"SIZE_{file_size}_BYTES")
        
        # Dosyayı şifrele
        encrypted_file_path, key = encrypt_file(file_path)
        log_info(f"Dosya şifrelendi: {file_path}")
        print(f"🔒 Dosya şifrelendi: {encrypted_file_path}")
        
        analyzer.send_marker_packet("ENCRYPTION", "FILE_ENCRYPTED_AES256")
        
        # Dosyayı parçalara böl
        chunks = split_file(encrypted_file_path)
        part_count = len(chunks)
        
        analyzer.send_marker_packet("CHUNKS", f"TOTAL_{part_count}_PARTS")

        # 1. Parça sayısını gönder
        s.sendall(part_count.to_bytes(4, 'big'))
        print(f"📦 Dosya {part_count} parçaya bölündü.")

        # 2. Anahtar uzunluğunu ve anahtarı gönder
        s.sendall(len(key).to_bytes(4, 'big'))
        s.sendall(key)
        print(f"🗝️ Anahtar gönderildi: {key.hex()[:16]}... (uzunluk: {len(key)} bayt)")
        
        analyzer.send_marker_packet("KEY_SENT", f"LENGTH_{len(key)}")

        # 3. Kimlik doğrulama tokenı gönder
        auth_token = generate_auth_token(key)
        s.sendall(len(auth_token).to_bytes(4, 'big'))
        s.sendall(auth_token)
        print(f"🔑 Kimlik doğrulama token'ı gönderildi ({len(auth_token)} byte).")
        
        analyzer.send_marker_packet("AUTH_TOKEN", f"SENT_{len(auth_token)}_BYTES")

        # 4. Dosya parçalarını sırayla gönder
        analyzer.send_marker_packet("DATA_TRANSFER", "CHUNKS_START")
        
        for i, chunk in enumerate(chunks):
            checksum = calculate_checksum(chunk)
            assert len(checksum) == 64, "Checksum uzunluğu 64 karakter olmalı"

            # Chunk uzunluğu (4 byte) gönder
            s.sendall(len(chunk).to_bytes(4, 'big'))
            # Chunk verisini gönder
            s.sendall(chunk)
            # Checksum gönder
            s.sendall(checksum.encode('ascii'))

            print(f"📤 Parça {i+1}/{part_count} gönderildi | Boyut: {len(chunk)} | Checksum: {checksum[:8]}...")
            packet_count += 1
            
            # Transfer ilerlemesini işaretle
            analyzer.monitor_transfer_progress(part_count, i)
            
            # Her 5 pakette bir kısa bekleme (Wireshark analizi için)
            if i % 5 == 0:
                time.sleep(0.1)
            
        analyzer.send_marker_packet("DATA_TRANSFER", "CHUNKS_COMPLETE")
        
        s.close()
        print("🔒 Bağlantı kapatıldı.")
        
        analyzer.send_marker_packet("TRANSFER_COMPLETE", f"SUCCESS_{packet_count}_PACKETS")
        print("✅ Gönderme işlemi başarıyla tamamlandı!")

        # Transfer başarılı - metrikleri kaydet
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"""
📊 Transfer İstatistikleri:
   ➤ Süre: {duration:.2f} saniye
   ➤ Paket Sayısı: {packet_count}
   ➤ Dosya Boyutu: {file_size} bytes
   ➤ Ortalama Hız: {(file_size/1024)/duration:.2f} KB/s
        """)
        
        try:
            metrics = MetricsManager()
            metrics.save_metrics(
                filename=os.path.basename(file_path),
                file_size=file_size,
                duration=duration,
                packet_count=packet_count,
                mode='TCP',
                success=True
            )
        except Exception as metrics_error:
            print(f"⚠️ Metrikler kaydedilemedi: {metrics_error}")

    except ConnectionRefusedError:
        print("❌ Bağlantı reddedildi! Önce receiver.py'yi çalıştırın.")
        analyzer.send_marker_packet("ERROR", "CONNECTION_REFUSED")
        
    except FileNotFoundError as e:
        print(f"❌ Dosya bulunamadı: {e}")
        analyzer.send_marker_packet("ERROR", f"FILE_NOT_FOUND_{e}")
        
    except Exception as e:
        log_error(f"Bir hata oluştu: {e}")
        print(f"❌ Hata: {type(e).__name__}: {e}")
        analyzer.send_marker_packet("ERROR", f"{type(e).__name__}_{str(e)[:50]}")
        
    finally:
        # Wireshark analyzer'ı kapat
        analyzer.send_marker_packet("SESSION_END", "SENDER_SHUTDOWN")
        analyzer.close()
        print("🔍 Wireshark analizi tamamlandı.")

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Güvenli Dosya Gönderici (Wireshark Enhanced)")
    print("=" * 60)
    print("🔍 Wireshark'ta şu filtreler kullanabilirsiniz:")
    print("   • tcp.port == 5001 (Ana TCP trafiği)")
    print("   • udp.port == 5002 (UDP marker ve test paketleri)")
    print("   • udp contains \"MARKER\" (Marker paketleri)")
    print("   • udp contains \"HEARTBEAT\" (Heartbeat paketleri)")
    print("   • udp contains \"FRAG\" (Fragment test paketleri)")
    print("=" * 60)
    start_sender()