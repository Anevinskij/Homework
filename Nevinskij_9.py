from scapy.all import sniff, wrpcap

# Функция для обработки каждого пакета
def packet_callback(packet):
    if packet.haslayer("TCP") and packet.haslayer("Raw"):
        print(f"Captured packet: {packet.summary()}")

# Запускаем перехват HTTP-трафика (порт 80)
packets = sniff(filter="tcp port 80", prn=packet_callback, store=1, timeout=60)

# Сохраняем собранные пакеты в файл .pcap
output_file = "http_traffic.pcap"
wrpcap(output_file, packets)

print(f"Трафик успешно сохранен в файл: {output_file}")