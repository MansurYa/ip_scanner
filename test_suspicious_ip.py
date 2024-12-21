from scapy.all import IP, ICMP, send

# Подозрительный IP-адрес
suspicious_ip = "192.168.1.100"

# Отправка ICMP Echo Request (ping) от подозрительного IP
packet = IP(src=suspicious_ip, dst="192.168.1.1")/ICMP()
send(packet, verbose=False)
print(f"Отправлен ICMP пакет от {suspicious_ip}")
