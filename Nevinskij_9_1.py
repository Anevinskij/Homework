from scapy.all import rdpcap
import html

# Загрузка файла .pcap
def load_pcap(file_path):
    try:
        packets = rdpcap(file_path)
        print(f"Файл {file_path} успешно загружен.")
        return packets
    except FileNotFoundError:
        print(f"Ошибка: Файл {file_path} не найден.")
        return None
    except Exception as e:
        print(f"Ошибка при загрузке файла: {e}")
        return None

# Поиск следов XSS-атаки
def find_xss_in_traffic(packets):
    xss_payloads = [
        "<img src=\"nonexistent.jpg\" onerror=\"alert('XSS')\">",
        "<img src=&quot;nonexistent.jpg&quot; onerror=&quot;alert(&apos;XSS&apos;)&quot;>",
        "onerror",
        "alert('XSS')"
    ]
    found_attacks = []

    for packet in packets:
        if packet.haslayer("TCP") and packet.haslayer("Raw"):
            try:
                # Декодирование данных из слоя Raw
                payload = packet["Raw"].load.decode('utf-8', errors='ignore')
                decoded_payload = html.unescape(payload) 

                # Проверяем наличие payload'ов XSS
                for keyword in xss_payloads:
                    if keyword in decoded_payload:
                        found_attacks.append({
                            "packet_summary": packet.summary(),
                            "decoded_payload": decoded_payload,
                            "payload_found": keyword
                        })
                        print(f"Найдена потенциальная XSS-атака: {keyword}")
            except Exception as e:
                print(f"Ошибка обработки пакета: {e}")

    return found_attacks

# Вывод результатов
def display_results(found_attacks):
    if not found_attacks:
        print("Следы XSS-атаки не найдены.")
    else:
        print("\nРезультаты анализа:")
        for i, attack in enumerate(found_attacks, start=1):
            print(f"\nАтака #{i}:")
            print(f"   Сводка пакета: {attack['packet_summary']}")
            print(f"   Найденный payload: {attack['payload_found']}")
            print(f"   Полезная нагрузка: {attack['decoded_payload']}")

# Основной скрипт
if __name__ == "__main__":
    pcap_file = "http_traffic.pcap" 
    packets = load_pcap(pcap_file)

    if packets:
        print("Начинаем анализ трафика...")
        found_attacks = find_xss_in_traffic(packets)
        display_results(found_attacks)