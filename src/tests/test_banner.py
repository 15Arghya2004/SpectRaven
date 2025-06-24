# tests/test_banner.py
import unittest
from unittest.mock import patch, MagicMock
from spectraven.banner import BannerGrabber

class TestBannerGrabber(unittest.TestCase):
    def setUp(self):
        self.banner_grabber = BannerGrabber(timeout=1)
    
    @patch('socket.socket')
    def test_tcp_banner_grab(self, mock_socket):
        # Mock banner response
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n'
        mock_socket.return_value = mock_sock
        
        result = self.banner_grabber._tcp_banner_grab('127.0.0.1', 80)
        self.assertIn('Apache', result)