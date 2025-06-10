import logging
import os

# Log dosyasının bulunduğu dizini belirt
log_dir = os.path.join(os.getcwd(), 'logs')  # 'logs' adında bir klasör oluşturulacak
if not os.path.exists(log_dir):  # Eğer klasör yoksa oluştur
    os.makedirs(log_dir)

# Log dosyasının tam yolu
log_file = os.path.join(log_dir, 'file_transfer.log')

# Logging yapılandırması
logging.basicConfig(
    filename=log_file,  # Log dosyasının adı ve yolu
    level=logging.INFO,  # Log seviyesini belirleyebilirsin (INFO, ERROR, DEBUG vb.)
    format="%(asctime)s - %(levelname)s - %(message)s"  # Log formatı
)

def log_info(message):
    logging.info(message)

def log_error(message):
    logging.error(message)

def log_warning(message):
    logging.warning(message)

def log_debug(message):
    logging.debug(message)
