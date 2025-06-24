# tests/test_scanner.py
import unittest
from unittest.mock import patch, MagicMock
from spectraven.scanner import PortScanner

class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = PortScanner(timeout=1, threads=10)
    
    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        # Mock open port
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock
        
        result = self.scanner._scan_port('127.0.0.1', 80)
        self.assertTrue(result)
    
    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        # Mock closed port
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_socket.return_value = mock_sock
        
        result = self.scanner._scan_port('127.0.0.1', 80)
        self.assertFalse(result)