# spectraven/scanner.py
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self, timeout=1, threads=50):
        self.timeout = timeout
        self.threads = threads
    
    def scan_host(self, host, ports):
        """Scan ports on a single host"""
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(lambda port: self._scan_port(host, port), ports)
            
        for port, is_open in zip(ports, results):
            if is_open:
                open_ports.append(port)
        
        return sorted(open_ports)
    
    def _scan_port(self, host, port):
        """Scan a single port using TCP connect"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def syn_scan_port(self, host, port):
        """SYN scan using raw sockets (requires root)"""
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
            
            # Create SYN packet
            syn_packet = IP(dst=host) / TCP(dport=port, flags="S")
            
            # Send packet and wait for response
            response = sr1(syn_packet, timeout=self.timeout, verbose=False)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 18:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(dst=host) / TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=self.timeout, verbose=False)
                    return True
            
            return False
        except:
            # Fallback to connect scan
            return self._scan_port(host, port)