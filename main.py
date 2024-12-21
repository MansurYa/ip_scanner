import json
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, ICMP, send
import time


class NetworkMonitor:
    def __init__(self, config, log_callback):
        self.interface = config.get("interface", "eth0")
        self.rules = config.get("rules", {})
        self.log = log_callback
        self.blocked_ips = set()
        self.port_scan_tracker = {}
        self.lock = threading.Lock()

    def start_sniffing(self):
        sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        sniff_thread.start()

    def sniff_packets(self):
        self.log("Начинаю прослушивание на интерфейсе: {}".format(self.interface))
        sniff(iface=self.interface, prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            pkt_size = len(packet)

            # Проверка на подозрительный IP
            if ip_src in self.rules.get("suspicious_ips", []):
                self.log("Подозрительный IP обнаружен: {}".format(ip_src))
                self.block_ip(ip_src)

            # Проверка на подозрительный порт
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport

                if tcp_sport in self.rules.get("suspicious_ports", []):
                    self.log("Подозрительный исходящий порт обнаружен: {}".format(tcp_sport))
                    self.block_ip(ip_src)

                if tcp_dport in self.rules.get("suspicious_ports", []):
                    self.log("Подозрительный входящий порт обнаружен: {}".format(tcp_dport))
                    self.block_ip(ip_src)

            # Проверка на размер пакета
            if pkt_size > self.rules.get("max_packet_size", 1500):
                self.log("Аномально большой пакет обнаружен от {}: размер {} байт".format(ip_src, pkt_size))
                self.block_ip(ip_src)

            # Проверка на сканирование портов
            with self.lock:
                if ip_src not in self.port_scan_tracker:
                    self.port_scan_tracker[ip_src] = set()

                if TCP in packet:
                    port = packet[TCP].dport
                    self.port_scan_tracker[ip_src].add(port)
                    if len(self.port_scan_tracker[ip_src]) > self.rules.get("port_scan_threshold", 100):
                        self.log("Сканирование портов обнаружено от {}: {} портов".format(ip_src, len(self.port_scan_tracker[ip_src])))
                        self.block_ip(ip_src)

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.log("Блокирую IP: {}".format(ip))
            # Отправка ICMP Destination Unreachable
            icmp_pkt = IP(dst=ip)/ICMP(type=3, code=1)
            send(icmp_pkt, verbose=False)
            self.log("Отправлено ICMP Destination Unreachable для {}".format(ip))
            # Дополнительно можно добавить iptables правило
            # Например:
            # subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])


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
            messagebox.showerror("Ошибка", "Не удалось загрузить config.json: {}".format(e))
            self.destroy()
            return

        # Создание элементов интерфейса
        self.log_area = scrolledtext.ScrolledText(self, state='disabled')
        self.log_area.pack(expand=True, fill='both')

        self.status_label = tk.Label(self, text="Статус: Ожидание запуска", anchor='w')
        self.status_label.pack(fill='x')

        self.start_button = tk.Button(self, text="Запустить Монитор", command=lambda: self.start_monitoring(config))
        self.start_button.pack(side='left', padx=10, pady=10)

        self.stop_button = tk.Button(self, text="Остановить Монитор", command=self.stop_monitoring, state='disabled')
        self.stop_button.pack(side='left', padx=10, pady=10)

        self.monitor = None

    def log(self, message):
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        self.log_area.configure(state='normal')
        self.log_area.insert(tk.END, "{} {}\n".format(timestamp, message))
        self.log_area.configure(state='disabled')
        self.log_area.see(tk.END)

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
            # Scapy не предоставляет прямого способа остановить sniff
            # Поэтому перезагрузим приложение
            self.log("Остановка монитора невозможна. Перезапустите программу.")
            messagebox.showinfo("Информация", "Остановка монитора невозможна. Перезапустите программу.")
            # Альтернативно, можно использовать глобальные флаги для управления sniff
            # Но для простоты предлагаем перезапуск


if __name__ == "__main__":
    app = Application()
    app.mainloop()
