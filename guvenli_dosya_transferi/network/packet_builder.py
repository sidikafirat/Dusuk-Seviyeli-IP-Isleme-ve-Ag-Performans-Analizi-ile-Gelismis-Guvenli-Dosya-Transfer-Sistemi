def build_packet(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    # Basit bir paket: dosya adı + ayırıcı + içerik
    file_name = file_path.split("/")[-1].encode()
    separator = b"<SEPARATOR>"

    packet = file_name + separator + data
    return packet
