import socket
import json
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Variables
        self.target_ip = tk.StringVar(value='192.168.1.1')
        self.start_port = tk.IntVar(value=1)
        self.end_port = tk.IntVar(value=1024)
        self.timeout = tk.IntVar(value=3)
        self.protocol = tk.StringVar(value='UDP')
        self.is_scanning = False

        # Widgets
        ttk.Label(self, text="Target IP:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.target_ip).grid(row=0, column=1)

        ttk.Label(self, text="Start Port:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.start_port).grid(row=1, column=1)

        ttk.Label(self, text="End Port:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.end_port).grid(row=2, column=1)

        ttk.Label(self, text="Timeout (TCP):").grid(row=3, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.timeout).grid(row=3, column=1)

        ttk.Label(self, text="Protocol:").grid(row=4, column=0, sticky=tk.W)
        protocol_combobox = ttk.Combobox(self, textvariable=self.protocol, values=["UDP", "TCP"], state="readonly")
        protocol_combobox.grid(row=4, column=1, sticky=tk.W)
        protocol_combobox.current(0)

        self.scan_button = ttk.Button(self, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=5, column=0)

        self.stop_button = ttk.Button(self, text="Stop Scan", command=self.stop_scanning, state=tk.DISABLED)
        self.stop_button.grid(row=5, column=1)

        self.progress = ttk.Progressbar(self, mode='determinate', maximum=100)
        self.progress.grid(row=6, columnspan=2, sticky=(tk.W, tk.E))

        self.log_view = tk.Text(self, width=50, height=10)
        self.log_view.grid(row=7, columnspan=2)
        
        self.clear_log_button = ttk.Button(self, text="Clear Log", command=self.clear_log)
        self.clear_log_button.grid(row=9, column=1)

        self.save_results_button = ttk.Button(self, text="Save Results", command=self.save_results)
        self.save_results_button.grid(row=9, column=2)

    def on_close(self):
        if not self.is_scanning:
            self.destroy()

    def start_scan(self):
        if not self.is_scanning:
            self.is_scanning = True
            self.scan_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            scan_thread = threading.Thread(target=self.scan_ports_thread, daemon=True)
            scan_thread.start()

    def stop_scanning(self):
        self.is_scanning = False

    def scan_ports_thread(self):
        target_ip = self.target_ip.get()
        start_port = self.start_port.get()
        end_port = self.end_port.get()
        timeout = self.timeout.get()
        protocol = self.protocol.get()

        if protocol == "UDP":
            scan_udp_ports(target_ip, start_port, end_port, self.log_view, self.progress, self)
        else:
            scan_tcp_ports(target_ip, start_port, end_port, timeout, self.log_view, self.progress, self)

        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def clear_log(self):
        self.log_view.delete(1.0, tk.END)

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])

        if file_path:
            with open(file_path, "w") as results_file:
                results_file.write(self.log_view.get(1.0, tk.END))

    def stop_scanning(self):
        self.is_scanning = False

def scan_udp_ports(target_ip, start_port, end_port, log_view, progress, app):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)  # Set a short timeout for receiving a response
    port_count = end_port - start_port + 1

    for index, port in enumerate(range(start_port, end_port + 1)):
        if not app.is_scanning:
            break

        addr = (target_ip, port)
        try:
            message = "UDP Test"
            sock.sendto(message.encode('utf-8'), addr)

            # Try to receive a response
            data, server = sock.recvfrom(1024)
            log_view.insert(tk.END, f'Tested UDP port {port} - Response\n')
        except socket.timeout:
            log_view.insert(tk.END, f'Tested UDP port {port} - No response\n')
        except Exception as e:
            log_view.insert(tk.END, f'Error testing UDP port {port}: {e}\n')

        progress['value'] = (index + 1) * 100 / port_count

    sock.close()

def scan_tcp_ports(target_ip, start_port, end_port, timeout, log_view, progress, app):
    port_count = end_port - start_port + 1

    for index, port in enumerate(range(start_port, end_port + 1)):
        if not app.is_scanning:
            break

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        addr = (target_ip, port)

        try:
            sock.connect(addr)
            log_view.insert(tk.END, f'TCP port {port} is open\n')
        except socket.timeout:
            log_view.insert(tk.END, f'TCP port {port} is closed or filtered\n')
        except Exception as e:
            log_view.insert(tk.END, f'Error testing TCP port {port}: {e}\n')
        finally:
            sock.close()

        progress['value'] = (index + 1) * 100 / port_count

if __name__ == '__main__':
    app = PortScannerApp()
    app.mainloop()
