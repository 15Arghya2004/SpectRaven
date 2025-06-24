
# tests/test_discovery.py
import unittest
from unittest.mock import patch, MagicMock
from spectraven.discovery import NetworkDiscovery

class TestNetworkDiscovery(unittest.TestCase):
    def setUp(self):
        self.discovery = NetworkDiscovery(timeout=1, threads=10)
    
    @patch('spectraven.discovery.srp')
    def test_arp_scan_success(self, mock_srp):
        # Mock successful ARP scan
        mock_response = MagicMock()
        mock_response.psrc = '192.168.1.1'
        mock_srp.return_value = [[(None, mock_response)]]
        
        result = self.discovery._arp_scan('192.168.1.0/24')
        self.assertEqual(result, ['192.168.1.1'])
    
    @patch('subprocess.run')
    def test_ping_sweep(self, mock_run):
        # Mock successful ping
        mock_run.return_value = MagicMock(returncode=0)
        
        result = self.discovery._ping_sweep('192.168.1.1/30')
        # Should find the host we mocked
        self.assertIn('192.168.1.2', result)