import json
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, ICMP, send
import time
import subprocess
import sys


class NetworkMonitor:
    """
    Класс для мониторинга сетевого трафика, анализа пакетов и блокировки подозрительных IP.
    """
    def __init__(self, config, log_callback):
        """
        Инициализация сетевого монитора.

        :param config: Конфигурация для мониторинга (например, интерфейс, правила).
        :param log_callback: Функция для записи логов.
        """
        self.interface = config.get("interface", "eth0")
        self.rules = config.get("rules", {})
        self.log = log_callback
        self.blocked_ips = set()
        self.port_scan_tracker = {}
        self.lock = threading.Lock()
        self.stop_sniffing = threading.Event()

    def start_sniffing(self):
        """
        Запуск процесса прослушивания сетевого трафика в отдельном потоке.
        """
        sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        sniff_thread.start()

    def sniff_packets(self):
        """
        Начало прослушивания пакетов на указанном интерфейсе.
        """
        self.log(f"Начинаю прослушивание на интерфейсе: {self.interface}")
        try:
            sniff(iface=self.interface, prn=self.process_packet, store=False, stop_filter=self.should_stop)
        except Exception as e:
            self.log(f"Ошибка при прослушивании пакетов: {e}")

    def should_stop(self, packet):
        return self.stop_sniffing.is_set()

    def process_packet(self, packet):
        """
        Обработка пакетов: проверка на подозрительные активности (необычные IP, порты, размер и сканирование портов).

        :param packet: Сетевой пакет для анализа.
        :return: None
        """
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                pkt_size = len(packet)

                # Проверка на подозрительный IP
                if ip_src in self.rules.get("suspicious_ips", []):
                    self.log(f"Подозрительный IP обнаружен: {ip_src}")
                    self.block_ip(ip_src)

                # Проверка на подозрительный порт
                if TCP in packet:
                    tcp_sport = packet[TCP].sport
                    tcp_dport = packet[TCP].dport

                    if tcp_sport in self.rules.get("suspicious_ports", []):
                        self.log(f"Подозрительный исходящий порт обнаружен: {tcp_sport}")
                        self.block_ip(ip_src)

                    if tcp_dport in self.rules.get("suspicious_ports", []):
                        self.log(f"Подозрительный входящий порт обнаружен: {tcp_dport}")
                        self.block_ip(ip_src)

                # Проверка на размер пакета
                if pkt_size > self.rules.get("max_packet_size", 1500):
                    self.log(f"Аномально большой пакет обнаружен от {ip_src}: размер {pkt_size} байт")
                    self.block_ip(ip_src)

                # Проверка на сканирование портов
                with self.lock:
                    if ip_src not in self.port_scan_tracker:
                        self.port_scan_tracker[ip_src] = set()

                    if TCP in packet:
                        port = packet[TCP].dport
                        self.port_scan_tracker[ip_src].add(port)
                        if len(self.port_scan_tracker[ip_src]) > self.rules.get("port_scan_threshold", 100):
                            self.log(f"Сканирование портов обнаружено от {ip_src}: {len(self.port_scan_tracker[ip_src])} портов")
                            self.block_ip(ip_src)
        except Exception as e:
            self.log(f"Ошибка при обработке пакета: {e}")

    def block_ip(self, ip):
        """
        Блокировка подозрительного IP, отправка ICMP сообщения.

        :param ip: IP-адрес, который нужно заблокировать.
        :return: None
        """
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.log(f"Блокирую IP: {ip}")
            try:
                # Отправка ICMP Destination Unreachable
                icmp_pkt = IP(dst=ip)/ICMP(type=3, code=1)
                send(icmp_pkt, verbose=False)
                self.log(f"Отправлено ICMP Destination Unreachable для {ip}")

                # Добавление iptables правила для блокировки IP
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                self.log(f"Добавлено iptables правило для блокировки IP: {ip}")
            except subprocess.CalledProcessError as e:
                self.log(f"Ошибка при добавлении iptables правила для {ip}: {e}")
            except Exception as e:
                self.log(f"Не удалось заблокировать IP {ip}: {e}")

    def stop(self):
        self.stop_sniffing.set()
        self.log("Запрос на остановку мониторинга отправлен.")


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Сетевой Монитор")
        self.geometry("800x600")

        # Чтение конфигурации
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить config.json: {e}")
            self.destroy()
            sys.exit(1)

        # Создание элементов интерфейса
        self.log_area = scrolledtext.ScrolledText(self, state='disabled')
        self.log_area.pack(expand=True, fill='both')

        self.status_label = tk.Label(self, text="Статус: Ожидание запуска", anchor='w')
        self.status_label.pack(fill='x')

        button_frame = tk.Frame(self)
        button_frame.pack(side='left', padx=10, pady=10)

        self.start_button = tk.Button(button_frame, text="Запустить Монитор", command=lambda: self.start_monitoring(config))
        self.start_button.pack(side='top', pady=5)

        self.stop_button = tk.Button(button_frame, text="Остановить Монитор", command=self.stop_monitoring, state='disabled')
        self.stop_button.pack(side='top', pady=5)

        # Открытие файла для записи логов
        try:
            self.log_file = open("network_monitor.log", "a")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть файл логов: {e}")
            self.destroy()
            sys.exit(1)

        self.monitor = None

        # Обработка закрытия окна
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log(self, message):
        """
        Запись сообщения в логовое окно интерфейса.
        """
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        log_message = f"{timestamp} {message}\n"
        self.log_area.configure(state='normal')
        self.log_area.insert(tk.END, log_message)
        self.log_area.configure(state='disabled')
        self.log_area.see(tk.END)
        try:
            self.log_file.write(log_message)
            self.log_file.flush()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось записать в файл логов: {e}")

    def start_monitoring(self, config):
        if not self.monitor:
            self.monitor = NetworkMonitor(config, self.log)
            self.monitor.start_sniffing()
            self.log("Монитор запущен.")
            self.status_label.config(text="Статус: Монитор запущен")
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')

    def stop_monitoring(self):
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
            self.log("Монитор остановлен.")
            self.status_label.config(text="Статус: Монитор остановлен")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def on_closing(self):
        if self.monitor:
            self.monitor.stop()
        if self.log_file:
            try:
                self.log_file.close()
            except:
                pass
        self.destroy()


if __name__ == "__main__":
    app = Application()
    app.mainloop()
