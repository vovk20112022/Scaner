import requests
import socket
from bs4 import BeautifulSoup
import whois
import argparse

def get_ip_address(url):
    try:
        print(f"[DEBUG] Получаем IP-адрес для: {url}")
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.gaierror as e:
        print(f"[ERROR] Ошибка получения IP-адреса: {e}")
        return None

def get_creation_date(url):
    try:
        print(f"[DEBUG] Получаем дату создания домена для: {url}")
        domain = whois.whois(url)
        if isinstance(domain.creation_date, list):
            return domain.creation_date[0]
        else:
            return domain.creation_date
    except (whois.parser.PywhoisError, TypeError) as e:
        print(f"[ERROR] Ошибка получения даты создания домена: {e}")
        return None

def scan_website(url):
    print("[+] Починаем сканування веб-сайта:", url)

    # Получение IP-адреса сайта
    ip_address = get_ip_address(url)
    if ip_address:
        print("[+] IP-адрес сайта:", ip_address)
    else:
        print("[-] Не удалось определить IP-адрес сайта")

    # Получение даты создания сайта
    creation_date = get_creation_date(url)
    if creation_date:
        print("[+] Приблизительная дата создания сайта:", creation_date)
    else:
        print("[-] Не удалось определить дату создания сайта")

    # Проверка доступности веб-сайта
    try:
        print(f"[DEBUG] Пытаемся подключиться к сайту: {url}")
        response = requests.get(url)
        print(f"[DEBUG] Код ответа: {response.status_code}")
        if response.status_code == 200:
            print("[+] Веб-сайт доступен")
        else:
            print("[-] Веб-сайт недоступен")
    except requests.ConnectionError as e:
        print(f"[-] Сайт недоступен. Ошибка: {e}")
        return

    # Поиск уязвимостей на веб-страницах
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Поиск уязвимостей XSS
        if '<script>' in response.text:
            print("[-] Обнаружена потенциальная XSS уязвимость на странице:", url)

        # Поиск уязвимостей SQL-инъекции
        if 'SQL syntax' in response.text:
            print("[-] Обнаружена уязвимость SQL-инъекции на странице:", url)

        # Проверка ссылок на странице
        links = soup.find_all('a')
        external_links = []
        for link in links:
            href = link.get('href')
            if href and href.startswith('http'):
                external_links.append(href)

        if len(external_links) > 5:
            print("[+] Найдено", len(external_links), "внешних ссылок на странице", url)
            for i in range(5):
                print("[+] Внешняя ссылка:", external_links[i])
            print("[+] И еще", len(external_links) - 5, "ссылок")
        else:
            for link in external_links:
                print("[+] Внешняя ссылка:", link)

    except requests.ConnectionError as e:
        print(f"[-] Нет доступа к сайту. Ошибка: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Сканирование веб-сайта на уязвимости")
    parser.add_argument("url", type=str, help="URL сайта для сканирования")
    args = parser.parse_args()

    scan_website(args.url)
