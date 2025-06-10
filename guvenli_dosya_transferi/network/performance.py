import subprocess
import re
import json
import platform
import os

# Windows'ta logger modülü yerine basit logging
def log_info(message):
    print(f"[INFO] {message}")

def log_error(message):
    print(f"[ERROR] {message}")

# 🕓 RTT (Round-Trip Time) ölçümü - Windows uyumlu
def measure_rtt(host="8.8.8.8", count=4):
    print(f"[*] Measuring RTT to {host}...")
    
    # Windows ve Linux için farklı ping komutları
    if platform.system() == "Windows":
        cmd = ["ping", "-n", str(count), host]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='cp437')
        
        # Windows ping çıktısını parse et
        # Örnek: "Ortalama = 23ms"
        match = re.search(r"Ortalama = (\d+)ms", result.stdout)
        if not match:
            # İngilizce Windows için
            match = re.search(r"Average = (\d+)ms", result.stdout)
        
        if match:
            avg_rtt = float(match.group(1))
            print(f"[+] RTT: {avg_rtt} ms (avg)")
            return avg_rtt
        else:
            print("[-] RTT measurement failed.")
            print(f"Debug - Ping output: {result.stdout}")
            return None
    else:
        # Linux/macOS için orijinal kod
        cmd = ["ping", "-c", str(count), host]
        result = subprocess.run(cmd, capture_output=True, text=True)
        match = re.search(r"rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)", result.stdout)
        if match:
            print(f"[+] RTT: {match.group(2)} ms (avg)")
            return float(match.group(2))
        else:
            print("[-] RTT measurement failed.")
            return None

# 🚀 Bant genişliği ölçümü (iPerf ile) - Windows kontrollü
def measure_bandwidth(host, port=5201, duration=10):
    """iPerf3 ile bant genişliği ve ağ metriklerini ölçer"""
    try:
        # iPerf3'ün kurulu olup olmadığını kontrol et
        try:
            subprocess.run(["iperf3", "--version"], capture_output=True)
        except FileNotFoundError:
            log_error("iPerf3 kurulu değil. Kurulum gerekli.")
            if platform.system() == "Windows":
                log_info("Windows için: https://iperf.fr/iperf-download.php adresinden indirebilirsiniz")
            else:
                log_info("Linux için: sudo apt-get install iperf3")
            return None
        
        cmd = ["iperf3", "-c", host, "-p", str(port), "-t", str(duration), "-J"]
        result = subprocess.run(cmd, capture_output=True, text=True)
                
        if result.returncode != 0:
            raise Exception(f"iPerf hatası: {result.stderr}")
                    
        data = json.loads(result.stdout)
                
        metrics = {
            'bandwidth_mbps': data['end']['sum_sent']['bits_per_second'] / 1e6,
            'jitter_ms': data['end']['sum_sent'].get('jitter_ms', 0),
            'packet_loss': data['end']['sum_sent'].get('lost_percent', 0),
            'retransmits': data['end']['sum_sent'].get('retransmits', 0)
        }
        log_info(f"Ağ ölçümü tamamlandı: {metrics}")
        return metrics
            
    except Exception as e:
        log_error(f"Ağ ölçüm hatası: {str(e)}")
        return None

# 🕳️ Paket kaybı ve tıkanıklık simülasyonu - Windows'ta çalışmaz
def simulate_packet_loss(interface="lo", loss_percent=10):
    if platform.system() == "Windows":
        print("❌ Paket kaybı simülasyonu Windows'ta desteklenmiyor.")
        print("💡 Bu özellik sadece Linux'ta tc komutu ile çalışır.")
        return False
    
    print(f"[*] Simulating {loss_percent}% packet loss on {interface}...")
    try:
        cmd = ["sudo", "tc", "qdisc", "add", "dev", interface, "root", "netem", "loss", f"{loss_percent}%"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Packet loss simulation applied.")
            return True
        else:
            print(f"[-] Simulation failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def clear_tc(interface="lo"):
    if platform.system() == "Windows":
        print("❌ Traffic control Windows'ta desteklenmiyor.")
        return False
    
    print(f"[*] Clearing traffic control rules on {interface}...")
    try:
        cmd = ["sudo", "tc", "qdisc", "del", "dev", interface, "root"]
        subprocess.run(cmd, capture_output=True)
        print("[+] Traffic control cleared.")
        return True
    except Exception as e:
        print(f"[-] Clear failed: {e}")
        return False

# 📊 Kablolu vs Kablosuz kıyaslama - Geliştirilmiş
def compare_interfaces():
    print("[*] Comparing RTT on different network connections...")
    
    print("📶 Testing current connection...")
    first_test = measure_rtt("8.8.8.8")
    
    if first_test is None:
        print("❌ İlk test başarısız oldu.")
        return
    
    print(f"✅ İlk bağlantı RTT: {first_test} ms")
    
    input("\n🔁 Lütfen farklı bir ağ bağlantısına geç (WiFi<->Ethernet) ve Enter'a bas...")
    
    print("🔌 Testing new connection...")
    second_test = measure_rtt("8.8.8.8")
    
    if second_test is None:
        print("❌ İkinci test başarısız oldu.")
        return
    
    print(f"✅ İkinci bağlantı RTT: {second_test} ms")
    
    # Sonuçları karşılaştır
    print(f"\n{'='*50}")
    print("📊 SONUÇLAR:")
    print(f"🥇 İlk bağlantı: {first_test} ms")
    print(f"🥈 İkinci bağlantı: {second_test} ms")
    
    difference = abs(first_test - second_test)
    percentage = (difference / min(first_test, second_test)) * 100
    
    if first_test < second_test:
        print(f"🏆 İlk bağlantı {difference:.1f}ms (%{percentage:.1f}) daha hızlı!")
    elif second_test < first_test:
        print(f"🏆 İkinci bağlantı {difference:.1f}ms (%{percentage:.1f}) daha hızlı!")
    else:
        print("🤝 Her iki bağlantı da eşit performans gösteriyor.")

# 🧪 Tüm testleri çalıştır
def run_all_tests():
    print("🚀 TÜM AĞ PERFORMANS TESTLERİ")
    print("="*50)
    
    # 1. RTT Testi
    print("\n1️⃣ RTT (Ping) Testi:")
    rtt = measure_rtt()
    
    # 2. Bağlantı karşılaştırması
    print("\n2️⃣ Bağlantı Karşılaştırması:")
    compare_interfaces()
    
    # 3. Bandwidth testi (iPerf gerekli)
    print("\n3️⃣ Bandwidth Testi:")
    print("⚠️ Bu test için iPerf3 sunucusu gerekiyor.")
    test_server = input("iPerf3 sunucu adresi (boş bırakırsanız atlanır): ").strip()
    
    if test_server:
        bandwidth = measure_bandwidth(test_server)
        if bandwidth:
            print(f"📊 Bandwidth: {bandwidth['bandwidth_mbps']:.2f} Mbps")
    
    # 4. Sistem bilgisi
    print(f"\n4️⃣ Sistem Bilgisi:")
    print(f"💻 OS: {platform.system()} {platform.release()}")
    print(f"🏗️ Architecture: {platform.architecture()[0]}")
    
    print("\n✅ Tüm testler tamamlandı!")

# Ana program
if __name__ == "__main__":
    print("🌐 AĞ PERFORMANS TEST ARACI")
    print("="*40)
    print("1. RTT (Ping) Testi")
    print("2. Bağlantı Karşılaştırması") 
    print("3. Bandwidth Testi (iPerf gerekli)")
    print("4. Paket Kaybı Simülasyonu (Sadece Linux)")
    print("5. Tüm Testler")
    print("6. Çıkış")
    
    while True:
        try:
            choice = input("\nSeçiminiz (1-6): ").strip()
            
            if choice == "1":
                measure_rtt()
            elif choice == "2":
                compare_interfaces()
            elif choice == "3":
                host = input("iPerf3 sunucu adresi: ").strip()
                if host:
                    measure_bandwidth(host)
                else:
                    print("❌ Sunucu adresi gerekli!")
            elif choice == "4":
                if platform.system() != "Windows":
                    interface = input("Interface (varsayılan: lo): ").strip() or "lo"
                    loss = input("Paket kaybı % (varsayılan: 10): ").strip() or "10"
                    simulate_packet_loss(interface, int(loss))
                    input("Test için Enter'a basın...")
                    clear_tc(interface)
                else:
                    print("❌ Bu özellik Windows'ta desteklenmiyor.")
            elif choice == "5":
                run_all_tests()
            elif choice == "6":
                print("👋 Çıkış yapılıyor...")
                break
            else:
                print("❌ Geçersiz seçim!")
                
        except KeyboardInterrupt:
            print("\n\n👋 Program sonlandırıldı.")
            break
        except Exception as e:
            print(f"❌ Hata: {e}")