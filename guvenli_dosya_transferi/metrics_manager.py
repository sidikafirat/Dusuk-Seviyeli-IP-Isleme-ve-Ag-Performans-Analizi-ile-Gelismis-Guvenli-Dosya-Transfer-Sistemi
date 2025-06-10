import json
import os
import time
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

class MetricsManager:
    def __init__(self, metrics_file="transfer_metrics.json"):
        self.metrics_file = metrics_file
        self.metrics = self.load_metrics()
    
    def load_metrics(self):
        """Mevcut metrikleri yükle"""
        if os.path.exists(self.metrics_file):
            try:
                with open(self.metrics_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                return []
        return []
    
    def save_metrics(self, filename, file_size, duration, packet_count, mode='TCP', success=True):
        """Transfer metriklerini kaydet"""
        # Minimum duration kontrolü (çok küçük süreleri düzelt)
        if duration < 0.001:  # 1ms'den küçükse
            duration = 0.001
        
        # Transfer hızını hesapla (MB/s)
        transfer_speed_bps = file_size / duration  # bytes per second
        transfer_speed_mbps = transfer_speed_bps / (1024 * 1024)  # MB/s
        
        metric = {
            'timestamp': datetime.now().isoformat(),
            'filename': filename,
            'file_size': file_size,
            'file_size_mb': file_size / (1024 * 1024),
            'duration': duration,
            'transfer_speed_mbps': transfer_speed_mbps,
            'transfer_speed_kbps': transfer_speed_bps / 1024,
            'packet_count': packet_count,
            'mode': mode,
            'success': success,
            'throughput_mbps': (file_size * 8) / (duration * 1_000_000)  # Mbps (megabits per second)
        }
        
        self.metrics.append(metric)
        
        # Dosyaya kaydet
        try:
            with open(self.metrics_file, 'w', encoding='utf-8') as f:
                json.dump(self.metrics, f, indent=2, ensure_ascii=False)
            print(f"📊 Metrikler kaydedildi: {transfer_speed_mbps:.3f} MB/s")
        except Exception as e:
            print(f"⚠️ Metrik kaydetme hatası: {e}")
    
    def get_statistics(self):
        """Transfer istatistiklerini hesapla"""
        if not self.metrics:
            return {
                'total_transfers': 0,
                'successful_transfers': 0,
                'avg_speed_mbps': 0,
                'max_speed_mbps': 0,
                'min_speed_mbps': 0,
                'success_rate': 0,
                'avg_packet_count': 0,
                'total_data_mb': 0
            }
        
        successful_metrics = [m for m in self.metrics if m['success']]
        speeds = [m['transfer_speed_mbps'] for m in successful_metrics]
        packet_counts = [m['packet_count'] for m in successful_metrics]
        file_sizes = [m['file_size_mb'] for m in self.metrics]
        
        return {
            'total_transfers': len(self.metrics),
            'successful_transfers': len(successful_metrics),
            'avg_speed_mbps': np.mean(speeds) if speeds else 0,
            'max_speed_mbps': max(speeds) if speeds else 0,
            'min_speed_mbps': min(speeds) if speeds else 0,
            'success_rate': (len(successful_metrics) / len(self.metrics)) * 100,
            'avg_packet_count': np.mean(packet_counts) if packet_counts else 0,
            'total_data_mb': sum(file_sizes)
        }
    
    def create_performance_graphs(self):
        """Performans grafiklerini oluştur"""
        try:
            if not self.metrics:
                print("📊 Grafik için yeterli veri yok")
                return
            
            # Grafik boyutunu ayarla
            plt.style.use('default')
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('Dosya Transfer Performans Analizi', fontsize=16, fontweight='bold')
            
            # Başarılı transferleri filtrele
            successful_metrics = [m for m in self.metrics if m['success']]
            
            if not successful_metrics:
                print("📊 Başarılı transfer bulunamadı")
                return
            
            # 1. Transfer Hızları (Zaman Serisi)
            timestamps = [datetime.fromisoformat(m['timestamp']) for m in successful_metrics]
            speeds = [m['transfer_speed_mbps'] for m in successful_metrics]
            
            ax1.plot(timestamps, speeds, 'b-o', linewidth=2, markersize=6)
            ax1.set_title('Transfer Hızları (Zaman Serisi)', fontweight='bold')
            ax1.set_xlabel('Zaman')
            ax1.set_ylabel('Hız (MB/s)')
            ax1.grid(True, alpha=0.3)
            ax1.tick_params(axis='x', rotation=45)
            
            # 2. Dosya Boyutu vs Hız
            file_sizes = [m['file_size_mb'] for m in successful_metrics]
            
            ax2.scatter(file_sizes, speeds, c='red', s=80, alpha=0.7)
            ax2.set_title('Dosya Boyutu vs Transfer Hızı', fontweight='bold')
            ax2.set_xlabel('Dosya Boyutu (MB)')
            ax2.set_ylabel('Transfer Hızı (MB/s)')
            ax2.grid(True, alpha=0.3)
            
            # Trend çizgisi ekle
            if len(file_sizes) > 1:
                z = np.polyfit(file_sizes, speeds, 1)
                p = np.poly1d(z)
                ax2.plot(file_sizes, p(file_sizes), "r--", alpha=0.8, linewidth=2)
            
            # 3. Başarı/Başarısızlık Oranı (Pie Chart)
            success_data = [
                len([m for m in self.metrics if m['success']]),
                len([m for m in self.metrics if not m['success']])
            ]
            
            # Sadece sıfır olmayan değerleri göster
            labels = []
            values = []
            colors = []
            
            if success_data[0] > 0:
                labels.append(f'Başarılı ({success_data[0]})')
                values.append(success_data[0])
                colors.append('#2E8B57')  # Sea Green
            
            if success_data[1] > 0:
                labels.append(f'Başarısız ({success_data[1]})')
                values.append(success_data[1])
                colors.append('#DC143C')  # Crimson
            
            if values:
                wedges, texts, autotexts = ax3.pie(values, labels=labels, autopct='%1.1f%%', 
                                                 colors=colors, startangle=90)
                ax3.set_title('Transfer Başarı Oranı', fontweight='bold')
                
                # Text formatting
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')
            else:
                ax3.text(0.5, 0.5, 'Veri Yok', ha='center', va='center', transform=ax3.transAxes)
                ax3.set_title('Transfer Başarı Oranı', fontweight='bold')
            
            # 4. Throughput Histogram
            throughputs = [m['throughput_mbps'] for m in successful_metrics]
            
            if throughputs:
                n_bins = min(10, len(throughputs))  # Maksimum 10 bin
                ax4.hist(throughputs, bins=n_bins, color='skyblue', alpha=0.7, edgecolor='black')
                ax4.set_title('Throughput Dağılımı', fontweight='bold')
                ax4.set_xlabel('Throughput (Mbps)')
                ax4.set_ylabel('Frekans')
                ax4.grid(True, alpha=0.3)
                
                # Ortalama çizgisi
                mean_throughput = np.mean(throughputs)
                ax4.axvline(mean_throughput, color='red', linestyle='--', linewidth=2, 
                           label=f'Ortalama: {mean_throughput:.2f} Mbps')
                ax4.legend()
            else:
                ax4.text(0.5, 0.5, 'Veri Yok', ha='center', va='center', transform=ax4.transAxes)
                ax4.set_title('Throughput Dağılımı', fontweight='bold')
            
            # Layout düzenle
            plt.tight_layout()
            
            # Grafikleri kaydet
            graph_filename = f"performance_graphs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(graph_filename, dpi=300, bbox_inches='tight')
            print(f"✅ Performans grafikleri kaydedildi: {graph_filename}")
            
            # Grafikleri göster
            plt.show()
            
        except Exception as e:
            print(f"❌ Grafik oluşturulurken hata: {e}")
            import traceback
            print(f"🔍 Hata detayı:\n{traceback.format_exc()}")
    
    def print_summary(self):
        """Detaylı özet yazdır"""
        stats = self.get_statistics()
        
        print("=" * 50)
        print("📊 TRANSFER PERFORMANS ÖZETİ")  
        print("=" * 50)
        print(f"Toplam transfer sayısı: {stats['total_transfers']}")
        print(f"Başarılı transfer sayısı: {stats['successful_transfers']}")
        print(f"Ortalama transfer hızı: {stats['avg_speed_mbps']:.3f} MB/s")
        print(f"Maksimum transfer hızı: {stats['max_speed_mbps']:.3f} MB/s")
        print(f"Minimum transfer hızı: {stats['min_speed_mbps']:.3f} MB/s")
        print(f"Başarı oranı: {stats['success_rate']:.1f}%")
        print(f"Ortalama paket sayısı: {stats['avg_packet_count']:.0f}")
        print(f"Toplam transfer edilen veri: {stats['total_data_mb']:.3f} MB")
        print("=" * 50)
        
        # Son transferleri göster
        if self.metrics:
            print("\n📋 SON 5 TRANSFER:")
            print("-" * 80)
            print(f"{'Zaman':<20} {'Dosya':<15} {'Boyut(MB)':<10} {'Hız(MB/s)':<12} {'Durum':<8}")
            print("-" * 80)
            
            for metric in self.metrics[-5:]:
                timestamp = datetime.fromisoformat(metric['timestamp']).strftime('%H:%M:%S')
                filename = metric['filename'][:12] + "..." if len(metric['filename']) > 15 else metric['filename']
                file_size_mb = metric['file_size_mb']
                speed = metric['transfer_speed_mbps']
                status = "✅" if metric['success'] else "❌"
                
                print(f"{timestamp:<20} {filename:<15} {file_size_mb:<10.3f} {speed:<12.3f} {status:<8}")
    
    def clear_metrics(self):
        """Tüm metrikleri temizle"""
        self.metrics = []
        try:
            if os.path.exists(self.metrics_file):
                os.remove(self.metrics_file)
            print("🗑️ Tüm metrikler temizlendi")
        except Exception as e:
            print(f"❌ Metrik temizleme hatası: {e}")
    
    def export_to_csv(self, filename="transfer_metrics.csv"):
        """Metrikleri CSV'ye aktar"""
        try:
            import pandas as pd
            
            if not self.metrics:
                print("📊 Dışa aktarılacak veri yok")
                return
            
            df = pd.DataFrame(self.metrics)
            df.to_csv(filename, index=False, encoding='utf-8')
            print(f"📤 Metrikler CSV'ye aktarıldı: {filename}")
            
        except ImportError:
            print("❌ Pandas kütüphanesi gerekli: pip install pandas")
        except Exception as e:
            print(f"❌ CSV dışa aktarma hatası: {e}")

# Test fonksiyonu
def create_test_data():
    """Test verileri oluştur"""
    manager = MetricsManager()
    
    # Çeşitli boyutlarda test dosyaları simüle et
    test_files = [
        ("small_file.txt", 1024, 0.001),      # 1KB, 1ms
        ("medium_file.pdf", 1024*1024, 0.1),  # 1MB, 100ms
        ("large_file.zip", 10*1024*1024, 2.5), # 10MB, 2.5s
        ("huge_file.mkv", 100*1024*1024, 15.0) # 100MB, 15s
    ]
    
    for filename, size, duration in test_files:
        packets = max(1, size // 1024)  # Her 1KB için 1 paket
        manager.save_metrics(filename, size, duration, packets, 'TCP', True)
    
    # Bir başarısız transfer ekle
    manager.save_metrics("failed_file.txt", 5*1024*1024, 3.0, 0, 'TCP', False)
    
    print("✅ Test verileri oluşturuldu!")
    return manager

if __name__ == "__main__":
    # Mevcut metrikleri göster
    manager = MetricsManager()
    
    if not manager.metrics:
        print("📊 Mevcut metrik bulunamadı. Test verileri oluşturuluyor...")
        manager = create_test_data()
    
    manager.print_summary()
    manager.create_performance_graphs()