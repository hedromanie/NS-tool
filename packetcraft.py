import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
import threading
import time
import os
import socket

class PacketCraftingTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Crafting Tool")
        self.root.geometry("800x700")
        root.iconbitmap("images.ico")
        
        self.center_window()
        self.show_warning()
        
        self.protocol_var = tk.StringVar(value="TCP")
        self.dest_ip_var = tk.StringVar(value="192.168.1.1")
        self.dest_mac_var = tk.StringVar(value="ff:ff:ff:ff:ff:ff")
        self.src_ip_var = tk.StringVar(value="192.168.1.100")
        self.src_mac_var = tk.StringVar(value="")
        self.src_port_var = tk.IntVar(value=12345)
        self.dest_port_var = tk.IntVar(value=80)
        self.ttl_var = tk.IntVar(value=64)
        self.packet_size_var = tk.IntVar(value=64)
        self.packet_count_var = tk.IntVar(value=1)
        self.interval_var = tk.DoubleVar(value=1.0)
        self.sending = False
        self.send_thread = None
        
        self.tcp_flags = {
            "FIN": tk.BooleanVar(),
            "SYN": tk.BooleanVar(value=True),
            "RST": tk.BooleanVar(),
            "PSH": tk.BooleanVar(),
            "ACK": tk.BooleanVar(),
            "URG": tk.BooleanVar()
        }
        
        self.packets_sent = 0
        self.start_time = None
        
        self.setup_ui()
        
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def show_warning(self):
        warning_text = (
            "ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ\n\n"
            "Этот инструмент предназначен ТОЛЬКО для:\n"
            "• Тестирования собственных сетей\n"
            "• Образовательных целей\n"
            "• Легальных пентестов с разрешения\n\n"
            "Требования для работы:\n"
            "• Права администратора/root\n"
            "• Установленный Npcap/WinPcap\n"
            "• Корректно настроенный сетевой интерфейс\n\n"
            "Неправомерное использование ЗАПРЕЩЕНО!"
        )
        messagebox.showwarning("Предупреждение безопасности", warning_text)
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        ttk.Label(main_frame, text="Сетевой интерфейс:").grid(row=0, column=0, sticky='w', pady=8, padx=5)
        # Меняем на обычный Combobox (без readonly) для ручного ввода любых интерфейсов
        self.iface_combo = ttk.Combobox(main_frame, width=30)
        self.iface_combo.grid(row=0, column=1, sticky='ew', pady=8, padx=5, columnspan=2)
        
        ttk.Button(main_frame, text="Обновить", command=self.update_interfaces, width=12).grid(row=0, column=3, padx=5)
        
        ttk.Label(main_frame, text="Протокол:").grid(row=1, column=0, sticky='w', pady=5, padx=5)
        protocol_combo = ttk.Combobox(main_frame, textvariable=self.protocol_var, 
                                    values=["TCP", "UDP", "ICMP", "ARP", "RAW"], 
                                    state="readonly", width=20)
        protocol_combo.grid(row=1, column=1, sticky='w', pady=5, padx=5)
        protocol_combo.bind('<<ComboboxSelected>>', self.on_protocol_change)
        
        ttk.Label(main_frame, text="TTL:").grid(row=1, column=2, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.ttl_var, width=8).grid(row=1, column=3, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="IP источника:").grid(row=2, column=0, sticky='w', pady=5, padx=5)
        src_ip_frame = ttk.Frame(main_frame)
        src_ip_frame.grid(row=2, column=1, sticky='ew', pady=5, padx=5)
        ttk.Entry(src_ip_frame, textvariable=self.src_ip_var, width=20).pack(side='left')
        ttk.Button(src_ip_frame, text="Авто", command=self.get_local_ip, width=6).pack(side='left', padx=5)
        
        ttk.Label(main_frame, text="MAC источника:").grid(row=2, column=2, sticky='w', pady=5, padx=5)
        src_mac_frame = ttk.Frame(main_frame)
        src_mac_frame.grid(row=2, column=3, sticky='ew', pady=5, padx=5)
        ttk.Entry(src_mac_frame, textvariable=self.src_mac_var, width=20).pack(side='left')
        ttk.Button(src_mac_frame, text="Авто", command=self.get_local_mac, width=6).pack(side='left', padx=5)
        
        ttk.Label(main_frame, text="IP получателя:").grid(row=3, column=0, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.dest_ip_var, width=20).grid(row=3, column=1, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="MAC получателя:").grid(row=3, column=2, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.dest_mac_var, width=20).grid(row=3, column=3, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="Порт источника:").grid(row=4, column=0, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.src_port_var, width=10).grid(row=4, column=1, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="Порт получателя:").grid(row=4, column=2, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.dest_port_var, width=10).grid(row=4, column=3, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="Размер пакета (байт):").grid(row=5, column=0, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.packet_size_var, width=10).grid(row=5, column=1, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="Количество пакетов:").grid(row=5, column=2, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.packet_count_var, width=10).grid(row=5, column=3, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="Интервал (сек):").grid(row=6, column=0, sticky='w', pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.interval_var, width=10).grid(row=6, column=1, sticky='w', pady=5, padx=5)
        
        ttk.Label(main_frame, text="Флаги TCP:").grid(row=7, column=0, sticky='w', pady=10, padx=5)
        flags_frame = ttk.Frame(main_frame)
        flags_frame.grid(row=7, column=1, columnspan=3, sticky='w', pady=10, padx=5)
        
        for i, (flag, var) in enumerate(self.tcp_flags.items()):
            ttk.Checkbutton(flags_frame, text=flag, variable=var).grid(row=0, column=i, sticky='w', padx=10)
        
        ttk.Label(main_frame, text="Данные пакета:").grid(row=8, column=0, sticky='nw', pady=5, padx=5)
        self.data_text = scrolledtext.ScrolledText(main_frame, height=6, width=70)
        self.data_text.grid(row=8, column=1, columnspan=3, sticky='ew', pady=5, padx=5)
        self.data_text.insert('1.0', "Packet data")
        
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="Отправить пакет", command=self.send_single_packet).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Начать отправку", command=self.start_sending).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Остановить отправку", command=self.stop_sending).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Очистить лог", command=self.clear_log).pack(side='right', padx=5)
        ttk.Button(button_frame, text="Справка", command=self.show_help).pack(side='right', padx=5)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief='sunken', anchor='w')
        status_bar.pack(fill='x', padx=10, pady=5)
        
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, wrap=tk.WORD)
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.update_interfaces()
        
    def update_interfaces(self):
        try:
            interfaces = get_if_list()
            # Добавляем префикс \Device\NPF_ для интерфейсов вида {475F6DF8-...}
            formatted_interfaces = []
            for iface in interfaces:
                if iface.startswith('{') and iface.endswith('}'):
                    formatted_interfaces.append(f"\\Device\\NPF_{iface}")
                else:
                    formatted_interfaces.append(iface)
            
            self.iface_combo['values'] = formatted_interfaces
            if formatted_interfaces:
                self.iface_combo.set(formatted_interfaces[0])
                self.get_local_ip()
                self.get_local_mac()
            self.log("Список интерфейсов обновлен")
        except Exception as e:
            self.log(f"Ошибка получения интерфейсов: {str(e)}")
            
    def get_local_ip(self):
        try:
            iface = self.iface_combo.get()
            if iface:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0":
                    self.src_ip_var.set(ip)
        except:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                self.src_ip_var.set(local_ip)
            except:
                self.src_ip_var.set("192.168.1.100")
                
    def get_local_mac(self):
        try:
            iface = self.iface_combo.get()
            if iface:
                mac = get_if_hwaddr(iface)
                if mac and mac != "00:00:00:00:00:00":
                    self.src_mac_var.set(mac)
        except:
            self.src_mac_var.set("")
            
    def on_protocol_change(self, event):
        protocol = self.protocol_var.get()
        
        if protocol == "ARP":
            self.dest_port_var.set(0)
            self.status_var.set("ARP - протокол разрешения адресов")
        elif protocol == "ICMP":
            self.dest_port_var.set(0)
            self.status_var.set("ICMP - протокол управляющих сообщений")
        elif protocol == "TCP":
            self.dest_port_var.set(80)
            self.status_var.set("TCP - протокол управления передачей")
        elif protocol == "UDP":
            self.dest_port_var.set(53)
            self.status_var.set("UDP - протокол пользовательских датаграмм")
        elif protocol == "RAW":
            self.status_var.set("RAW - сырые пакеты")
            
    def validate_inputs(self):
        try:
            dest_ip = self.dest_ip_var.get()
            if not dest_ip:
                messagebox.showerror("Ошибка", "Введите IP адрес получателя")
                return False
                
            if self.protocol_var.get() in ["TCP", "UDP"]:
                src_port = self.src_port_var.get()
                dest_port = self.dest_port_var.get()
                if not (0 <= src_port <= 65535) or not (0 <= dest_port <= 65535):
                    messagebox.showerror("Ошибка", "Порты должны быть в диапазоне 0-65535")
                    return False
                    
            ttl = self.ttl_var.get()
            if ttl < 1 or ttl > 255:
                messagebox.showerror("Ошибка", "TTL должен быть в диапазоне 1-255")
                return False
                
            packet_size = self.packet_size_var.get()
            if packet_size < 1:
                messagebox.showerror("Ошибка", "Размер пакета должен быть положительным числом")
                return False
                
            interval = self.interval_var.get()
            if interval <= 0:
                messagebox.showerror("Ошибка", "Интервал должен быть положительным числом")
                return False
                
            packet_count = self.packet_count_var.get()
            if packet_count < 1:
                messagebox.showerror("Ошибка", "Количество пакетов должно быть положительным числом")
                return False
                
            return True
            
        except tk.TclError:
            messagebox.showerror("Ошибка", "Проверьте корректность введенных числовых значений")
            return False
        
    def get_tcp_flags(self):
        flags = 0
        if self.tcp_flags["FIN"].get(): flags |= 0x01
        if self.tcp_flags["SYN"].get(): flags |= 0x02
        if self.tcp_flags["RST"].get(): flags |= 0x04
        if self.tcp_flags["PSH"].get(): flags |= 0x08
        if self.tcp_flags["ACK"].get(): flags |= 0x10
        if self.tcp_flags["URG"].get(): flags |= 0x20
        return flags
        
    def craft_packet(self):
        try:
            protocol = self.protocol_var.get()
            dest_ip = self.dest_ip_var.get()
            dest_mac = self.dest_mac_var.get()
            src_ip = self.src_ip_var.get()
            src_mac = self.src_mac_var.get()
            packet_data = self.data_text.get('1.0', 'end-1c')
            
            packet = None
            
            if src_mac or dest_mac:
                ether_kwargs = {}
                if src_mac:
                    ether_kwargs['src'] = src_mac
                if dest_mac and dest_mac != "ff:ff:ff:ff:ff:ff":
                    ether_kwargs['dst'] = dest_mac
                packet = Ether(**ether_kwargs)
            else:
                packet = Ether()
            
            if protocol in ["TCP", "UDP", "ICMP"]:
                ip_kwargs = {'dst': dest_ip, 'ttl': self.ttl_var.get()}
                if src_ip and src_ip != "0.0.0.0":
                    ip_kwargs['src'] = src_ip
                packet = packet / IP(**ip_kwargs)
            
            if protocol == "TCP":
                tcp_kwargs = {
                    'sport': self.src_port_var.get(),
                    'dport': self.dest_port_var.get(),
                    'flags': self.get_tcp_flags()
                }
                packet = packet / TCP(**tcp_kwargs)
            elif protocol == "UDP":
                udp_kwargs = {
                    'sport': self.src_port_var.get(),
                    'dport': self.dest_port_var.get()
                }
                packet = packet / UDP(**udp_kwargs)
            elif protocol == "ICMP":
                packet = packet / ICMP()
            elif protocol == "ARP":
                arp_kwargs = {'pdst': dest_ip}
                if src_ip:
                    arp_kwargs['psrc'] = src_ip
                if src_mac:
                    arp_kwargs['hwsrc'] = src_mac
                packet = packet / ARP(**arp_kwargs)
                
            if packet_data and protocol != "ARP":
                data = packet_data.encode()[:self.packet_size_var.get()]
                if data:
                    packet = packet / Raw(load=data)
                
            return packet
            
        except Exception as e:
            self.log(f"Ошибка создания пакета: {str(e)}")
            return None
            
    def send_single_packet(self):
        if not self.validate_inputs():
            return
            
        if not self.iface_combo.get():
            messagebox.showerror("Ошибка", "Выберите сетевой интерфейс")
            return
            
        packet = self.craft_packet()
        if packet:
            try:
                iface = self.iface_combo.get()
                sendp(packet, iface=iface, verbose=0)
                self.packets_sent += 1
                self.log(f"Пакет отправлен через {iface}")
                self.log(f"Протокол: {self.protocol_var.get()}")
                self.log(f"Получатель: {self.dest_ip_var.get()}:{self.dest_port_var.get()}")
                self.log(f"Размер: {len(packet)} байт")
                self.log(f"TTL: {self.ttl_var.get()}")
            except Exception as e:
                self.log(f"Ошибка отправки: {str(e)}")
                if "No such device" in str(e):
                    self.log("СОВЕТ: Попробуйте выбрать другой сетевой интерфейс")
                elif "Permission" in str(e):
                    self.log("СОВЕТ: Запустите программу с правами администратора")
        
    def start_sending(self):
        if not self.validate_inputs():
            return
            
        if not self.iface_combo.get():
            messagebox.showerror("Ошибка", "Выберите сетевой интерфейс")
            return
            
        if self.sending:
            self.log("Отправка уже запущена")
            return
            
        self.sending = True
        self.start_time = time.time()
        self.send_thread = threading.Thread(target=self.sending_loop)
        self.send_thread.daemon = True
        self.send_thread.start()
        self.log("Начата непрерывная отправка пакетов")
        self.status_var.set("Отправка пакетов...")
        
    def stop_sending(self):
        if not self.sending:
            return
            
        self.sending = False
        if self.send_thread and self.send_thread.is_alive():
            self.send_thread.join(timeout=2.0)
        self.log("Остановка отправки пакетов...")
        self.status_var.set("Готов к работе")
        
    def sending_loop(self):
        packet_count = 0
        total_packets = self.packet_count_var.get()
        
        try:
            while self.sending and (total_packets == 0 or packet_count < total_packets):
                packet = self.craft_packet()
                if packet:
                    iface = self.iface_combo.get()
                    sendp(packet, iface=iface, verbose=0)
                    packet_count += 1
                    self.packets_sent += 1
                    
                    if packet_count % 10 == 0:
                        self.log(f"Отправлено пакетов: {packet_count}")
                    
                    time.sleep(self.interval_var.get())
                else:
                    break
                    
        except Exception as e:
            self.log(f"Ошибка в цикле отправки: {str(e)}")
            
        finally:
            self.sending = False
            elapsed_time = time.time() - self.start_time if self.start_time else 0
            self.log(f"Отправка завершена. Всего отправлено: {packet_count} пакетов")
            self.log(f"Время работы: {elapsed_time:.2f} секунд")
            if elapsed_time > 0:
                self.log(f"Скорость: {packet_count/elapsed_time:.2f} пакетов/сек")
            
    def clear_log(self):
        self.log_text.delete('1.0', tk.END)
        self.log("Лог очищен")
        
    def show_help(self):
        help_text = """
СПРАВКА ПО ИСПОЛЬЗОВАНИЮ:

Основные функции:
• Отправить пакет - отправляет один пакет
• Начать отправку - непрерывная отправка
• Остановить отправку - останавливает отправку

Параметры:
• Сетевой интерфейс - выбор интерфейса для отправки
• Протокол - тип отправляемого пакета
• IP/MAC адреса - адреса источника и получателя
• Порты - для TCP/UDP протоколов
• TTL - время жизни пакета

Советы:
• Всегда проверяйте выбранный интерфейс
• Для RAW пакетов укажите MAC адреса
"""
        messagebox.showinfo("Справка", help_text.strip())
            
    def log(self, message):
        if hasattr(self, 'log_text'):
            timestamp = time.strftime('%H:%M:%S')
            self.log_text.insert('end', f"[{timestamp}] {message}\n")
            self.log_text.see('end')
            self.root.update_idletasks()

def main():
    if os.name == 'posix' and os.geteuid() != 0:
        print("Внимание: Для работы на канальном уровне требуются права root")
        
    try:
        root = tk.Tk()
        app = PacketCraftingTool(root)
        
        def on_closing():
            if app.sending:
                if messagebox.askokcancel("Выход", "Отправка пакетов все еще активна. Вы уверены, что хотите выйти?"):
                    app.stop_sending()
                    root.destroy()
            else:
                root.destroy()
                
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
        
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        messagebox.showerror("Ошибка", f"Не удалось запустить приложение: {e}")

if __name__ == "__main__":
    main()