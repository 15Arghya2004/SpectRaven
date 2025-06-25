#!/usr/bin/env python3
"""
Network connectivity test script for SpectRaven
"""

import socket
import subprocess
import platform
import ipaddress

def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except:
        return "127.0.0.1"

def test_ping(host):
    """Test ping to a host"""
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            command = ['ping', '-n', '1', '-w', '3000', host]
        else:
            command = ['ping', '-c', '1', '-W', '3', host]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def test_tcp_connection(host, port):
    """Test TCP connection to host:port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def main():
    print("=== SpectRaven Network Test ===\n")
    
    # Get local network info
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")
    
    # Determine likely network range
    try:
        ip_obj = ipaddress.IPv4Address(local_ip)
        # Assume /24 network
        network_base = str(ip_obj).rsplit('.', 1)[0] + '.0/24'
        print(f"Suggested network range: {network_base}")
    except:
        network_base = "192.168.1.0/24"
        print(f"Default network range: {network_base}")
    
    print("\n=== Testing Connectivity ===")
    
    # Test ping to gateway (usually .1)
    gateway = str(ip_obj).rsplit('.', 1)[0] + '.1'
    print(f"Testing ping to gateway {gateway}...")
    if test_ping(gateway):
        print("✓ Gateway ping successful")
    else:
        print("✗ Gateway ping failed")
    
    # Test ping to Google DNS
    print("Testing ping to 8.8.8.8...")
    if test_ping("8.8.8.8"):
        print("✓ Internet connectivity OK")
    else:
        print("✗ Internet connectivity issue")
    
    # Test TCP connections to common local services
    print(f"\nTesting TCP connections on local network...")
    common_hosts = [
        str(ip_obj).rsplit('.', 1)[0] + '.1',  # Gateway
        str(ip_obj).rsplit('.', 1)[0] + '.100',  # Common IP
        str(ip_obj).rsplit('.', 1)[0] + '.254',  # Common IP
    ]
    
    for host in common_hosts:
        for port in [80, 443, 22]:
            if test_tcp_connection(host, port):
                print(f"✓ {host}:{port} - TCP connection successful")
    
    print(f"\n=== Recommended SpectRaven Commands ===")
    print(f"python run_spectraven.py discover --network {network_base}")
    print(f"python run_spectraven.py discover --network {network_base} --method tcp")
    print(f"python run_spectraven.py discover --network {network_base} --method both --timeout 5")
    
    # Test a small range first
    small_range = str(ip_obj).rsplit('.', 1)[0] + '.1-10'
    print(f"\nFor faster testing, try a smaller range first:")
    print(f"python run_spectraven.py discover --network {str(ip_obj).rsplit('.', 1)[0] + '.1/29'}")

if __name__ == '__main__':
    main()