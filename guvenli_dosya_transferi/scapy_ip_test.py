from scapy.all import IP, ICMP, send

packet = IP(dst="8.8.8.8", ttl=5, flags="MF", id=12345)  # MF: More Fragments
packet /= ICMP()

send(packet)
print("🚀 Fragmentation flag ve TTL ayarlandı, paket gönderildi.")