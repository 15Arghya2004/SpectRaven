import socket
import threading
import ipaddress
import subprocess
import platform
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkDiscovery:
    def __init__(self, timeout=1, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.live_hosts = []
        self.lock = threading.Lock()
    
    def discover_hosts(self, network):
        """Discover live hosts using multiple methods"""
        print(f"Starting discovery on {network}")
        
        # Skip ARP scan on Windows without proper drivers
        if platform.system().lower() == 'windows':
            print("Windows detected, using ping sweep method")
            return self._ping_sweep(network)
        
        # Try ARP scan first (most reliable for local networks)
        try:
            hosts = self._arp_scan(network)
            if hosts:
                return hosts
        except Exception as e:
            print(f"ARP scan failed: {e}")
        
        # Fallback to ping sweep
        print("Falling back to ping sweep")
        return self._ping_sweep(network)
    
    def _arp_scan(self, network):
        """ARP scan for local network discovery"""
        try:
            from scapy.all import ARP, Ether, srp, conf
            
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
            raise Exception(f"ARP scan error: {e}")
    
    def _ping_sweep(self, network):
        """Ping sweep using threading"""
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            
            # Limit hosts for testing (remove this in production)
            if len(hosts) > 254:
                print(f"Large network detected ({len(hosts)} hosts), limiting to first 50 for testing")
                hosts = hosts[:50]
            
            print(f"Ping sweeping {len(hosts)} hosts with {self.threads} threads")
            
            # Use ThreadPoolExecutor for better control
            with ThreadPoolExecutor(max_workers=min(self.threads, 50)) as executor:
                # Submit all ping tasks
                future_to_host = {executor.submit(self._ping_host, host): host for host in hosts}
                
                # Collect results
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        if future.result():
                            with self.lock:
                                self.live_hosts.append(host)
                    except Exception as e:
                        print(f"Error pinging {host}: {e}")
            
            return sorted(self.live_hosts, key=lambda x: ipaddress.IPv4Address(x))
        except Exception as e:
            print(f"Ping sweep failed: {e}")
            return []
    
    def _ping_host(self, host):
        """Ping a single host - returns True if host is up"""
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                # Windows ping command
                command = ['ping', '-n', '1', '-w', str(self.timeout * 1000), host]
            else:
                # Linux/Unix ping command
                command = ['ping', '-c', '1', '-W', str(self.timeout), host]
            
            # Run ping command
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout + 2,
                creationflags=subprocess.CREATE_NO_WINDOW if system == 'windows' else 0
            )
            
            # Check if ping was successful
            success = result.returncode == 0
            if success:
                print(f"Host {host} is UP")
            
            return success
            
        except subprocess.TimeoutExpired:
            print(f"Ping timeout for {host}")
            return False
        except Exception as e:
            print(f"Ping error for {host}: {e}")
            return False
    
    def _tcp_ping(self, host, port=80):
        """TCP ping alternative - tries to connect to a common port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def discover_with_tcp_ping(self, network, ports=[80, 443, 22, 21, 25]):
        """Alternative discovery using TCP ping on common ports"""
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            
            print(f"TCP ping discovery on {len(hosts)} hosts")
            
            live_hosts = set()
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                for host in hosts:
                    for port in ports:
                        future = executor.submit(self._tcp_ping, host, port)
                        futures.append((future, host))
                
                for future, host in futures:
                    try:
                        if future.result():
                            live_hosts.add(host)
                            print(f"Host {host} responded on TCP")
                            break  # Host is up, no need to check other ports
                    except:
                        pass
            
            return sorted(list(live_hosts), key=lambda x: ipaddress.IPv4Address(x))
            
        except Exception as e:
            print(f"TCP ping discovery failed: {e}")
            return []