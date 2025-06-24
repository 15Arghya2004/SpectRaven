# spectraven/discovery.py
import socket
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp, conf
import subprocess
import platform

class NetworkDiscovery:
    def __init__(self, timeout=1, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.live_hosts = []
        self.lock = threading.Lock()
    
    def discover_hosts(self, network):
        """Discover live hosts using multiple methods"""
        try:
            # Try ARP scan first (most reliable for local networks)
            hosts = self._arp_scan(network)
            if hosts:
                return hosts
        except:
            pass
        
        # Fallback to ping sweep
        return self._ping_sweep(network)
    
    def _arp_scan(self, network):
        """ARP scan for local network discovery"""
        try:
            # Disable scapy verbose output
            conf.verb = 0
            
            # Create ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            # Send and receive
            result = srp(packet, timeout=self.timeout, verbose=False)[0]
            
            hosts = []
            for sent, received in result:
                hosts.append(received.psrc)
            
            return sorted(hosts, key=lambda x: ipaddress.IPv4Address(x))
        except Exception as e:
            print(f"ARP scan failed: {e}")
            return []
    
    def _ping_sweep(self, network):
        """Ping sweep using threading"""
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self._ping_host, hosts)
            
            return sorted(self.live_hosts, key=lambda x: ipaddress.IPv4Address(x))
        except Exception as e:
            print(f"Ping sweep failed: {e}")
            return []
    
    def _ping_host(self, host):
        """Ping a single host"""
        try:
            # Use system ping command
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-W' if platform.system().lower() == 'windows' else '-w', str(self.timeout), host]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout + 1)
            
            if result.returncode == 0:
                with self.lock:
                    self.live_hosts.append(host)
        except:
            pass