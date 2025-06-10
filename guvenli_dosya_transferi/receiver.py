import os
import socket
import hashlib
import time
import statistics
import platform
from crypto.encrypt import decrypt_file
from utils.logger import log_info, log_error
from crypto.key_generator import verify_auth_token

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001


def receive_udp_packets():
    # UDP socket oluştur
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind adres ve port
    listen_host = '127.0.0.1'  # localhost
    listen_port = 5001
    
    try:
        # Socket'i adrese bağla
        sock.bind((listen_host, listen_port))
        print(f"UDP Receiver listening on {listen_host}:{listen_port}")
        print("Press Ctrl+C to stop")
        
        while True:
            # Veri al
            data, addr = sock.recvfrom(1024)  # 1024 byte buffer
            
            print(f"Received from {addr}: {data.decode('utf-8')}")
            
    except KeyboardInterrupt:
        print("\nReceiver stopped by user")
    finally:
        sock.close()


def recv_all(sock, length):
    data = b""
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise EOFError("Bağlantı kapandı veya veri eksik")
        data += more
    return data

def verify_checksum(data, expected_checksum):
    actual_checksum = hashlib.sha256(data).hexdigest()
    return actual_checksum == expected_checksum

def manual_decrypt_with_debugging(encrypted_file_path, key):
    """Manuel deşifre işlemi - debug bilgileri ile"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        print(f"🔍 Debug: Anahtar uzunluğu: {len(key)} bayt")
        print(f"🔍 Debug: Anahtar (hex): {key.hex()}")
        
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        print(f"🔍 Debug: Şifrelenmiş veri uzunluğu: {len(encrypted_data)} bayt")
        
        if len(encrypted_data) < 16:
            print("❌ Şifrelenmiş veri çok küçük, IV bile yok")
            return None
            
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        print(f"🔍 Debug: IV (hex): {iv.hex()}")
        print(f"🔍 Debug: Ciphertext uzunluğu: {len(ciphertext)} bayt")
        
        if len(ciphertext) % 16 != 0:
            print(f"⚠️ Uyarı: Ciphertext uzunluğu AES block size'ın katı değil")
        
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key.ljust(16, b'\x00')
            elif len(key) > 32:
                key = key[:32]
            elif 16 < len(key) < 24:
                key = key[:16]
            elif 24 < len(key) < 32:
                key = key[:24]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        
        try:
            decrypted_data = unpad(decrypted_padded, AES.block_size)
        except ValueError:
            last_byte = decrypted_padded[-1]
            if last_byte == 0x20:
                decrypted_data = decrypted_padded.rstrip(b' ')
                print("✅ Metin dosyası padding'i kaldırıldı")
            elif 1 <= last_byte <= 16:
                padding_bytes = decrypted_padded[-last_byte:]
                if all(b == last_byte for b in padding_bytes):
                    decrypted_data = decrypted_padded[:-last_byte]
                else:
                    decrypted_data = decrypted_padded.rstrip(b' \x00')
            else:
                decrypted_data = decrypted_padded.rstrip(b' \x00')
        
        decrypted_path = "decrypted_file.txt"
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"🔓 Dosya manuel olarak deşifrelendi: {decrypted_path}")
        
        try:
            content_preview = decrypted_data[:100].decode('utf-8', errors='ignore')
            print(f"📄 İçerik önizlemesi: {content_preview}")
        except:
            print("📄 İçerik metin formatında değil")
        
        return decrypted_path
        
    except Exception as decrypt_error:
        print(f"❌ Manuel deşifre hatası: {decrypt_error}")
        import traceback
        print(f"🔍 Hata detayı:\n{traceback.format_exc()}")
        return None

def test_port_connectivity(host, port, timeout=3):
    """Port bağlantısını test et"""
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(timeout)
        result = test_socket.connect_ex((host, port))
        test_socket.close()
        return result == 0
    except:
        return False

def measure_rtt_basic(host='8.8.8.8', samples=4):
    """Temel RTT ölçümü - dış sunucu kullanarak"""
    try:
        import subprocess
        rtt_samples = []
        
        print(f"📡 RTT ölçümü başlatılıyor ({host})...")
        
        if platform.system() == 'Windows':
            cmd = ['ping', '-n', str(samples), host]
        else:
            cmd = ['ping', '-c', str(samples), host]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            output = result.stdout
            # RTT değerlerini çıkar
            for line in output.split('\n'):
                if 'time=' in line.lower() or 'süre=' in line.lower():
                    try:
                        if 'time=' in line:
                            rtt_str = line.split('time=')[1].split('ms')[0]
                        else:
                            rtt_str = line.split('süre=')[1].split('ms')[0]
                        rtt = float(rtt_str)
                        rtt_samples.append(rtt)
                    except:
                        continue
            
            if rtt_samples:
                return {
                    'min_rtt': min(rtt_samples),
                    'max_rtt': max(rtt_samples),
                    'avg_rtt': statistics.mean(rtt_samples),
                    'jitter': statistics.stdev(rtt_samples) if len(rtt_samples) > 1 else 0,
                    'successful_samples': len(rtt_samples),
                    'target': host
                }
        
        print(f"⚠️ Ping komutu başarısız veya RTT değerleri bulunamadı")
        return None
        
    except subprocess.TimeoutExpired:
        print("⚠️ Ping timeout")
        return None
    except Exception as e:
        print(f"❌ RTT ölçüm hatası: {e}")
        return None

def run_iperf3_windows(host, port=5201, duration=5):
    """Windows'ta iPerf3 testi - kısa süreli"""
    try:
        import subprocess
        import json
        
        print(f"🔧 iPerf3 bandwidth testi ({host}:{port})...")
        
        # Farklı iPerf3 yollarını dene
        possible_paths = [
            'iperf3',
            'iperf3.exe', 
            r'C:\Program Files\iperf3\iperf3.exe',
            r'C:\Users\Monter\Desktop\iperf3\iperf3.exe',
            r'C:\iperf3\iperf3.exe',
            './iperf3.exe'
        ]
        
        iperf_cmd = None
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    iperf_cmd = path
                    print(f"✅ iPerf3 bulundu: {path}")
                    break
            except:
                continue
        
        if not iperf_cmd:
            print("❌ iPerf3 bulunamadı - Bu test atlanacak")
            print("💡 iPerf3 kurmak için: https://iperf.fr/iperf-download.php")
            return None
        
        # Önce sunucu var mı kontrol et
        if not test_port_connectivity(host, port, timeout=2):
            print(f"⚠️ iPerf3 sunucusu ({host}:{port}) erişilebilir değil")
            print(f"💡 Ayrı terminal açıp çalıştırın: {iperf_cmd} -s -p {port}")
            return None
        
        cmd = [
            iperf_cmd, 
            '-c', host, 
            '-p', str(port),
            '-t', str(duration),
            '-J'  # JSON çıktısı
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            bandwidth_bps = data['end']['sum_received']['bits_per_second']
            return {
                'bandwidth_mbps': bandwidth_bps / 1_000_000,
                'bandwidth_kbps': bandwidth_bps / 1_000,
                'retransmits': data['end']['sum_sent'].get('retransmits', 0),
                'duration': duration,
                'iperf_path': iperf_cmd
            }
        else:
            print(f"⚠️ iPerf3 stderr: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        print("⚠️ iPerf3 timeout")
        return None
    except json.JSONDecodeError as e:
        print(f"⚠️ iPerf3 JSON parse hatası: {e}")
        return None
    except Exception as e:
        print(f"⚠️ iPerf3 hatası: {e}")
        return None

def simulate_network_conditions_windows():
    """Windows'ta ağ koşulları analizi"""
    try:
        print("🔧 Windows ağ analizi:")
        
        # 1. TCP ayarları
        try:
            import subprocess
            result = subprocess.run(['netsh', 'int', 'tcp', 'show', 'global'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("📊 TCP ayarları:")
                for line in result.stdout.split('\n'):
                    if any(keyword in line for keyword in ['Window', 'Scaling', 'Chimney']):
                        if line.strip():
                            print(f"   • {line.strip()}")
        except Exception as e:
            print(f"   ⚠️ TCP ayarları alınamadı: {e}")
        
        # 2. Ping ile ağ kalitesi testi
        try:
            print("📊 Ping ile ağ kalitesi testi:")
            host = '127.0.0.1'
            if platform.system() == 'Windows':
                cmd = ['ping', '-n', '5', host]
            else:
                cmd = ['ping', '-c', '5', host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output = result.stdout
                # Kayıp oranını bul
                for line in output.split('\n'):
                    if 'loss' in line.lower() or 'kayıp' in line.lower() or 'lost' in line.lower():
                        print(f"   • {line.strip()}")
                        break
        except subprocess.TimeoutExpired:
            print("   ⚠️ Ping timeout")
        except Exception as e:
            print(f"   ⚠️ Ping hatası: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Windows ağ analizi hatası: {e}")
        return False

def run_network_diagnostics():
    """Ağ teşhis testlerini çalıştır - sunucu başlatmadan önce"""
    print("🔍 Ağ teşhis testleri başlatılıyor...")
    
    # 1. Sistem bilgisi
    print(f"💻 Sistem: {platform.system()} {platform.release()}")
    
    # 2. Windows ağ analizi
    simulate_network_conditions_windows()
    
    # 3. İnternet RTT testi
    print("\n📊 RTT Testi:")
    rtt_results = measure_rtt_basic()
    if rtt_results:
        print(f"   ➔ Hedef: {rtt_results['target']}")
        print(f"   ➔ Min RTT: {rtt_results['min_rtt']:.2f} ms")
        print(f"   ➔ Max RTT: {rtt_results['max_rtt']:.2f} ms") 
        print(f"   ➔ Avg RTT: {rtt_results['avg_rtt']:.2f} ms")
        print(f"   ➔ Jitter: {rtt_results['jitter']:.2f} ms")
    else:
        print("   ❌ RTT ölçümü başarısız")
    
    # 4. iPerf3 durumu kontrolü
    print("\n📊 Bandwidth Test Hazırlığı:")
    iperf_results = run_iperf3_windows('127.0.0.1', 5201)
    if iperf_results:
        print(f"   ✅ iPerf3 testi başarılı: {iperf_results['bandwidth_mbps']:.2f} Mbps")
    else:
        print("   ℹ️ iPerf3 testi kullanılamıyor (normal)")

def start_receiver():
    print("\n" + "="*50)
    print("🔐 Güvenli Dosya Alıcı Başlatılıyor")
    print("="*50)
    
    # Ağ teşhis testleri - sunucu başlatmadan önce
    try:
        run_network_diagnostics()
    except Exception as net_e:
        print(f"⚠️ Ağ teşhis testleri atlandı: {net_e}")
    
    # Ana sunucu socket'i
    server_socket = None
    client_socket = None
    
    try:
        print("\n📡 Alıcı sunucu başlatılıyor...")
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(1)
        
        print(f"🌐 Sunucu başlatıldı: {SERVER_HOST}:{SERVER_PORT}")
        print("⏳ Dosya transferi için bağlantı bekleniyor...")
        
        # Bağlantı kabul et
        client_socket, client_address = server_socket.accept()
        print(f"✅ Bağlantı kuruldu: {client_address}")
        
        # Receive timeout ayarla
        client_socket.settimeout(30.0)
        
        # 1. Parça sayısını al
        print("📦 Parça sayısı alınıyor...")
        part_count_bytes = recv_all(client_socket, 4)
        part_count = int.from_bytes(part_count_bytes, 'big')
        print(f"📦 Toplam parça sayısı: {part_count}")
        
        # 2. Anahtar uzunluğunu ve anahtarı al
        print("🔑 Şifreleme anahtarı alınıyor...")
        key_length_bytes = recv_all(client_socket, 4)
        key_length = int.from_bytes(key_length_bytes, 'big')
        key = recv_all(client_socket, key_length)
        
        print(f"🔑 Anahtar alındı: {key.hex()[:16]}... (uzunluk: {len(key)} bayt)")
        
        # 3. Token uzunluğunu al
        print("🔐 Kimlik doğrulama token'ı alınıyor...")
        token_length_bytes = recv_all(client_socket, 4)
        token_length = int.from_bytes(token_length_bytes, 'big')
        
        # 4. Token verisini tam al
        auth_token = recv_all(client_socket, token_length)
        print(f"🔐 Kimlik doğrulama token'ı alındı ({token_length} bayt)")
        
        # 5. Token doğrulaması
        if verify_auth_token(auth_token, key):
            print("✔️ Kimlik doğrulama başarılı!")
        else:
            print("❌ Kimlik doğrulama başarısız, bağlantı sonlandırılıyor")
            return
        
        # 6. Dosya parçalarını al
        received_chunks = []
        total_bytes = 0
        
        print(f"\n📦 {part_count} parça alınıyor...")
        for i in range(part_count):
            print(f"📥 Parça {i+1}/{part_count} alınıyor...", end=" ")
            
            # Chunk uzunluğunu al
            chunk_len_bytes = recv_all(client_socket, 4)
            chunk_len = int.from_bytes(chunk_len_bytes, 'big')
            
            # Chunk verisini al
            chunk = recv_all(client_socket, chunk_len)
            total_bytes += chunk_len
            
            # Checksum'ı al (64 karakter = 64 bayt ASCII)
            checksum_bytes = recv_all(client_socket, 64)
            checksum = checksum_bytes.decode('ascii')
            
            # Checksum doğrulaması
            if verify_checksum(chunk, checksum):
                received_chunks.append(chunk)
                print(f"✅ Boyut: {chunk_len} bayt")
            else:
                print(f"❌ Checksum hatası")
                print(f"⚠️ Parça {i+1} doğrulaması başarısız, yoksayılıyor")
        
        print(f"\n📊 Transfer özeti:")
        print(f"   • Alınan parça: {len(received_chunks)}/{part_count}")
        print(f"   • Toplam boyut: {total_bytes:,} bayt")
        
        # 7. Parçaları birleştir ve dosyaya yaz
        print("🔧 Parçalar birleştiriliyor...")
        full_data = b''.join(received_chunks)
        output_path = "received_encrypted_file.bin"
        with open(output_path, "wb") as f:
            f.write(full_data)
        print(f"📂 Şifrelenmiş dosya kaydedildi: {output_path}")
        
        # 8. Dosyayı deşifre et
        print("🔓 Dosya deşifreleniyor...")
        decrypted_path = None
        try:
            decrypted_path = decrypt_file(output_path, key)
            print(f"🔓 Dosya deşifrelendi: {decrypted_path}")
        except Exception as e:
            print(f"🔧 Standart deşifre başarısız ({type(e).__name__}: {e})")
            print("🔧 Manuel deşifre deneniyor...")
            decrypted_path = manual_decrypt_with_debugging(output_path, key)
        
        if decrypted_path and decrypted_path != "DECRYPT_FAILED":
            log_info(f"Alınan dosya: {output_path}, Deşifrelenmiş dosya: {decrypted_path}")
            print("✅ Dosya transferi ve deşifreleme başarıyla tamamlandı!")
        else:
            print("❌ Deşifre işlemi başarısız")
            log_error("Dosya deşifre edilemedi")
        
    except socket.timeout:
        print("⏰ Bağlantı timeout - veri alınması çok uzun sürdü")
    except ConnectionResetError:
        print("🔌 Bağlantı gönderen tarafından sıfırlandı")
    except EOFError as e:
        print(f"📡 Bağlantı sorunu: {e}")
        print("💡 Gönderen uygulamanın çalıştığından emin olun")
    except KeyboardInterrupt:
        print("⛔ İşlem kullanıcı tarafından durduruldu")
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {type(e).__name__}: {str(e)}")
        log_error(f"Receiver hatası: {e}")
        import traceback
        print(f"🔍 Hata detayı:\n{traceback.format_exc()}")
    finally:
        # Temizlik
        if client_socket:
            try:
                client_socket.close()
                print("🔌 İstemci bağlantısı kapatıldı")
            except:
                pass
        
        if server_socket:
            try:
                server_socket.close()
                print("🌐 Sunucu socket'i kapatıldı")
            except:
                pass
        
        print("🏁 Alıcı işlemi sona erdi\n")

if __name__ == "__main__":
    print("=" * 50)
    print("🚀 Güvenli Dosya Alıcı")
    print("=" * 50)
    start_receiver()
    receive_udp_packets()