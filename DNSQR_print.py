import curses
from scapy.all import *

# Создаем словарь для хранения счетчиков доменных имен
dns_counters = {}

# Функция для обработки DNS-пакетов
def process_dns_packet(packet):
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0:
        qname = packet[DNSQR].qname.decode('utf-8')
        dns_counters[qname] = dns_counters.get(qname, 0) + 1

def main(stdscr):
    # Инициализируем curses
    curses.curs_set(0)
    stdscr.nodelay(1)
    
    while True:
        # Запускаем сниффер для DNS-трафика
        sniff(filter="udp port 53", prn=process_dns_packet, count=1)
        
        # Очищаем экран
        stdscr.clear()
        
        # Выводим топ-20 доменных имен
        sorted_dns = sorted(dns_counters.items(), key=lambda x: x[1], reverse=True)[:20]
        for i, (domain, count) in enumerate(sorted_dns, start=1):
            # Форматируем строку для вывода
            formatted_line = f"{domain.ljust(40)} {count}"
            stdscr.addstr(i, 0, formatted_line)
        
        # Обновляем экран
        stdscr.refresh()

# Запускаем curses
curses.wrapper(main)
