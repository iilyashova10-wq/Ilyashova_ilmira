import os
import requests
import json

# ==============================
# НАСТРОЙКИ
# ==============================

# ВАШ API КЛЮЧ
API_KEY = "d6c955d17adaf351eef2e453171d8c09f331d1f511a857d2e9f8435587919b30"

# ХЭШ ФАЙЛА (SHA256 тестового файла EICAR)
FILE_HASH = "44d88612fea8a8f36de82e1278abb02f"

if not API_KEY:
    raise ValueError("API ключ не найден!")

# Формируем запрос
url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"
headers = {"x-apikey": API_KEY}

# Отправляем запрос
response = requests.get(url, headers=headers)

if response.status_code == 200:
    # Получаем JSON-ответ
    data = response.json()

    # Выводим полный JSON (как требуется в задании)
    print("ПОЛНЫЙ JSON-ОТВЕТ:")
    print(json.dumps(data, indent=4))

    # Извлекаем статистику
    stats = data["data"]["attributes"]["last_analysis_stats"]

    # Выводим статистику (как требуется в задании)
    print("\nСТАТИСТИКА СКАНИРОВАНИЯ ФАЙЛА:")
    print(f"Вредоносных детектов: {stats['malicious']}")
    print(f"Подозрительных: {stats['suspicious']}")
    print(f"Безопасных: {stats['harmless']}")
    print(f"Неопределенных: {stats['undetected']}")

else:
    print(f"Ошибка: {response.status_code}")
    print(response.text)