# spectraven/banner.py
import socket
import ssl
import time

class BannerGrabber:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.service_probes = {
            21: b'',  # FTP
            22: b'',  # SSH
            23: b'',  # Telnet
            25: b'EHLO test\r\n',  # SMTP
            53: b'',  # DNS
            80: b'GET / HTTP/1.1\r\nHost: test\r\n\r\n',  # HTTP
            110: b'',  # POP3
            143: b'',  # IMAP
            443: b'GET / HTTP/1.1\r\nHost: test\r\n\r\n',  # HTTPS
            993: b'',  # IMAPS
            995: b'',  # POP3S
        }
    
    def grab_banner(self, host, port):
        """Grab service banner from host:port"""
        try:
            # Try SSL first for known SSL ports
            if port in [443, 993, 995]:
                banner = self._ssl_banner_grab(host, port)
                if banner:
                    return banner
            
            # Regular TCP banner grab
            return self._tcp_banner_grab(host, port)
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _tcp_banner_grab(self, host, port):
        """Grab banner using regular TCP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Send probe if available
            probe = self.service_probes.get(port, b'')
            if probe:
                sock.send(probe)
            
            # Receive banner
            time.sleep(0.5)  # Wait for response
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else f"Port {port} open"
        except:
            return None
    
    def _ssl_banner_grab(self, host, port):
        """Grab banner using SSL connection"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.connect((host, port))
                
                # Send probe
                probe = self.service_probes.get(port, b'')
                if probe:
                    ssock.send(probe)
                
                time.sleep(0.5)
                banner = ssock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                return banner if banner else f"SSL Port {port} open"
        except:
            return None