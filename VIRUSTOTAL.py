import os
import zipfile
import requests
import time

# ------------------КОНФИГУРАЦИЯ--------------------
API_KEY = "205da07cd7aa539937c2889e1aca83f27b17abbb4cd26bafc0bdca811292e8d6"  
ARCHIVE_PATH = "archive.zip"
EXTRACT_DIR = "extracted_files"  
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"  
TARGET_AVS = ["Fortinet", "McAfee", "Yandex", "Sophos"] 
REPORT_FILE = "analysis_report.txt"  # Файл для сохранения отчета

def extract_archive(password, archive_path, extract_dir):
    """
    Распаковывает защищенный паролем ZIP-архив
    :param password: Пароль от архива
    :param archive_path: Путь к архиву
    :param extract_dir: Папка для распаковки
    """
    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"Архив {archive_path} не найден!")
    
    # Создаем папку для распаковки, если ее нет
    os.makedirs(extract_dir, exist_ok=True)
    
    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(path=extract_dir, pwd=password.encode())
    print(f"Архив успешно распакован в {extract_dir}")

def upload_file(file_path):
    """
    Отправляет файл на анализ в VirusTotal
    :param file_path: Путь к файлу
    :return: ID анализа или None при ошибке
    """
    headers = {
        "x-apikey": API_KEY
    }
    
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(VT_UPLOAD_URL, headers=headers, files=files)
    
    if response.status_code == 200:
        return response.json()["data"]["id"]
    else:
        print(f"Ошибка загрузки файла: {response.status_code} - {response.text}")
        return None

def get_analysis_report(analysis_id):
    """
    Получает результаты анализа по ID
    :param analysis_id: ID анализа от VirusTotal
    :return: Словарь с результатами или None при ошибке
    """
    headers = {"x-apikey": API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data["data"]["attributes"]["status"] == "completed":
                return data
            time.sleep(30)  # Проверяем каждые 30 секунд
        else:
            print(f"Ошибка получения отчета: {response.status_code} - {response.text}")
            return None

def analyze_report(report_data, target_avs):
    """
    Анализирует отчет VirusTotal
    :param report_data: Данные отчета
    :param target_avs: Список антивирусов для проверки
    :return: Словарь с результатами анализа
    """
    results = {
        "detected": {},
        "target_avs_results": {},
        "sandbox_data": None,
        "network_data": None
    }
    
    # Данные о детектировании
    for av, res in report_data["data"]["attributes"]["results"].items():
        if res["category"] == "malicious":
            results["detected"][av] = res.get("result", "Unknown")
    
    # Проверка целевых антивирусов
    for av in target_avs:
        result = report_data["data"]["attributes"]["results"].get(av, {})
        results["target_avs_results"][av] = {
            "detected": result.get("category") == "malicious",
            "threat": result.get("result", "Not detected")
        }
    
    # Данные песочницы
    if "sandbox" in report_data["data"]["attributes"]:
        results["sandbox_data"] = report_data["data"]["attributes"]["sandbox"]
    
    # Сетевые взаимодействия
    if "network" in report_data["data"]["attributes"]:
        results["network_data"] = {
            "domains": report_data["data"]["attributes"]["network"].get("domains", []),
            "hosts": report_data["data"]["attributes"]["network"].get("hosts", [])
        }
    
    return results

def save_report_to_file(report_data, file_path):
    """
    Сохраняет отчет в текстовый файл
    :param report_data: Данные для сохранения
    :param file_path: Путь к файлу
    """
    with open(file_path, "w", encoding="utf-8") as f:
        for file_name, data in report_data.items():
            f.write(f"\nФайл: {file_name}\n")
            f.write(f"Всего обнаружений: {len(data['detected'])}\n")
            f.write("Обнаружившие антивирусы:\n")
            for av, threat in data["detected"].items():
                f.write(f"- {av}: {threat}\n")
            
            f.write("Результаты для целевых антивирусов:\n")
            for av, res in data["target_avs_results"].items():
                status = "Обнаружен" if res["detected"] else "Не обнаружен"
                f.write(f"- {av}: {status} ({res['threat']})\n")
            
            if data["network_data"]:
                f.write("\nСетевые взаимодействия:\n")
                f.write(f"Домены: {', '.join(data['network_data']['domains'])}\n")
                f.write(f"IP-адреса: {', '.join(data['network_data']['hosts'])}\n")
            f.write("-" * 50 + "\n")

def main():
    # Этап 1: Распаковка архива
    try:
        extract_archive("forensic", ARCHIVE_PATH, EXTRACT_DIR)
    except Exception as e:
        print(f"Ошибка распаковки: {e}")
        return
    
    # Этап 2-3: Анализ файлов
    all_results = {}
    for file_name in os.listdir(EXTRACT_DIR):
        file_path = os.path.join(EXTRACT_DIR, file_name)
        print(f"\nАнализируем файл: {file_name}")
        
        # Загрузка файла
        analysis_id = upload_file(file_path)
        if not analysis_id:
            continue
        
        report = get_analysis_report(analysis_id)
        if not report:
            continue
        
        # Анализ данных
        analysis = analyze_report(report, TARGET_AVS)
        all_results[file_name] = analysis
        
        # Вывод базовой информации
        print(f"\nДетектировали угрозу: {len(analysis['detected'])} антивирусов")
        print("Обнаружившие антивирусы:", ", ".join(analysis['detected']))
        
        print("Обнаруженные угрозы:")
        for av, threat in analysis["detected"].items():
            print(f"- {av}: {threat}")

        # Результаты для целевых AV
        print("\nРезультаты для целевых антивирусов:")
        for av, res in analysis["target_avs_results"].items():
            status = "Обнаружен" if res["detected"] else "Не обнаружен"
            print(f"- {av}: {status} ({res['threat']})" if res["detected"] else f"- {av}: {status}")
        
        # Сетевые взаимодействия
        if analysis["network_data"]:
            print("\nСетевые взаимодействия:")
            print("Домены:", ", ".join(analysis["network_data"]["domains"]))
            print("IP-адреса:", ", ".join(analysis["network_data"]["hosts"]))
    
    # Этап 4: Формирование отчета и сохранение в файл
    save_report_to_file(all_results, REPORT_FILE)
    print(f"\nИтоговый отчет сохранен в файл: {REPORT_FILE}")

if __name__ == "__main__":
    main()