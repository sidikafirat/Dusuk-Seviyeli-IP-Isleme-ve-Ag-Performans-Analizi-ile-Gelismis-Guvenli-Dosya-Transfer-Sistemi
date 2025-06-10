import socket
import threading
import time

def udp_listener():
    """UDP paketlerini dinle (Wireshark analizi için)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 5002))
        
        print("🔍 UDP Listener başlatıldı (Port: 5002)")
        print("📊 Wireshark marker paketlerini dinliyor...")
        
        while True:
            try:
                data, addr = sock.recvfrom(2048)
                message = data.decode('utf-8')
                timestamp = time.strftime('%H:%M:%S')
                
                if "MARKER" in message:
                    print(f"📍 [{timestamp}] MARKER: {message}")
                elif "HEARTBEAT" in message:
                    print(f"💓 [{timestamp}] HEARTBEAT: {message}")
                elif "FRAG" in message:
                    print(f"🧩 [{timestamp}] FRAGMENT: {message[:50]}...")
                elif "TTL_TEST" in message:
                    print(f"⏱️ [{timestamp}] TTL: {message}")
                elif "SIZE_TEST" in message:
                    print(f"📦 [{timestamp}] SIZE: {message[:30]}...")
                else:
                    print(f"📡 [{timestamp}] UDP: {message[:50]}...")
                    
            except UnicodeDecodeError:
                print(f"📡 [{timestamp}] UDP: Binary data received ({len(data)} bytes)")
            except Exception as e:
                print(f"⚠️ UDP listener hatası: {e}")
                
    except Exception as e:
        print(f"❌ UDP listener başlatılamadı: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    print("🔍 UDP Paket Dinleyici (Wireshark Analizi)")
    print("=" * 50)
    
    # UDP listener'ı ayrı thread'de çalıştır
    listener_thread = threading.Thread(target=udp_listener, daemon=True)
    listener_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 UDP Listener durduruluyor...")
        print("✅ Tamamlandı!")