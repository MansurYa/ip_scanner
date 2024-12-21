# Сетевой Монитор

## Описание

Сетевой Монитор — это инструмент для обнаружения и блокировки подозрительного сетевого трафика на основе заданных правил и сигнатур. Программа анализирует сетевые пакеты, выявляет аномалии, такие как подозрительные IP-адреса, порты, большие размеры пакетов и сканирование портов, и блокирует соответствующие IP-адреса.

## Установка

1. **Клонирование репозитория:**

    ```bash
    git clone <URL_репозитория>
    cd <папка_проекта>
    ```

2. **Установка зависимостей:**

    Убедитесь, что у вас установлен Python 3.9.

    ```bash
    sudo apt-get update
    sudo apt-get install python3-pip python3-tk build-essential libffi-dev python3-dev
    sudo pip3 install --upgrade pip
    sudo pip3 install scapy
    ```

## Конфигурация

Создайте файл `config.json` в корне проекта с содержимым:

```json
{
    "interface": "ens3",
    "rules": {
        "suspicious_ips": ["192.168.1.100", "10.0.0.200"],
        "suspicious_ports": [23, 80],
        "max_packet_size": 1500,
        "port_scan_threshold": 5
    }
}
```

Параметры:
	•	interface: Имя сетевого интерфейса для прослушивания (например, ens3).
	•	suspicious_ips: Список подозрительных IP-адресов.
	•	suspicious_ports: Список подозрительных портов.
	•	max_packet_size: Максимальный размер пакета в байтах.
	•	port_scan_threshold: Порог для определения сканирования портов.

Запуск

Запустите программу с правами суперпользователя:

sudo python3 main.py

Использование
	1.	Запуск мониторинга:
	•	Нажмите кнопку “Запустить Монитор” в графическом интерфейсе.
	2.	Остановка мониторинга:
	•	Нажмите кнопку “Остановить Монитор”. Обратите внимание, что остановка мониторинга невозможна без перезапуска программы.
	3.	Просмотр логов:
	•	Логи отображаются в окне приложения и сохраняются в файл network_monitor.log.

Тестирование

Для проверки работы программы используйте следующие тестовые скрипты:

1.	Отправка пакета с подозрительным IP:
```
from scapy.all import IP, ICMP, send

suspicious_ip = "192.168.1.100"
packet = IP(src=suspicious_ip, dst="192.168.1.1")/ICMP()
send(packet, verbose=False)
print(f"Отправлен ICMP пакет от {suspicious_ip}")
```

2.	Отправка пакета на подозрительный порт:
```
from scapy.all import IP, TCP, send

suspicious_ip = "192.168.1.101"
suspicious_port = 80
packet = IP(src=suspicious_ip, dst="192.168.1.1")/TCP(dport=suspicious_port, sport=12345)
send(packet, verbose=False)
print(f"Отправлен TCP пакет от {suspicious_ip} на порт {suspicious_port}")
```

3.	Отправка аномально большого пакета:
```
from scapy.all import IP, UDP, send

suspicious_ip = "192.168.1.102"
packet_size = 2000
packet = IP(src=suspicious_ip, dst="192.168.1.1")/UDP(dport=53)/("X" * (packet_size - 28))
send(packet, verbose=False)
print(f"Отправлен UDP пакет от {suspicious_ip} размером {packet_size} байт")
```

4.	Симуляция сканирования портов:
```
from scapy.all import IP, TCP, send

suspicious_ip = "192.168.1.103"
for port in range(1, 11):
    packet = IP(src=suspicious_ip, dst="192.168.1.1")/TCP(dport=port, sport=12345)
    send(packet, verbose=False)
    print(f"Отправлен TCP пакет от {suspicious_ip} на порт {port}")
```



Логи

Логи сохраняются в файл network_monitor.log и отображаются в интерфейсе приложения.

Примечания
	•	Для корректной работы программы требуется запуск с правами суперпользователя.
	•	Для удаления добавленных правил iptables используйте команды:

`sudo iptables -D INPUT -s <IP_адрес> -j DROP`


•	Будьте осторожны при изменении правил iptables, чтобы не нарушить сетевую безопасность системы.

