from scapy.all import *
import random

def send_fake_udp_packet():
    # Rastgele kaynak/destinasyon bilgileri
    src_ip = "192.168." + ".".join(map(str, (random.randint(0, 255) for _ in range(2))))
    dst_ip = "192.168.1.1"
    src_port = random.randint(1024, 65535)
    dst_port = 53  # DNS portu olarak ayarladık, istediğiniz portu seçebilirsiniz
    
    # Rastgele payload oluştur
    payload = bytes([random.randint(0, 255) for _ in range(random.randint(10, 100))])
    
    # IP ve UDP katmanlarını oluştur
    ip_layer = IP(src=src_ip, dst=dst_ip, ttl=64)
    udp_layer = UDP(sport=src_port, dport=dst_port)
    
    # Paketi oluştur ve gönder
    packet = ip_layer/udp_layer/Raw(load=payload)
    send(packet, verbose=False)
    print(f"Sahte UDP paketi gönderildi: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

if __name__ == "__main__":
    for _ in range(10):  # 10 sahte paket gönder
        send_fake_udp_packet()