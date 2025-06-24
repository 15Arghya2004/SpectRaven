# tests/test_checks.py
import unittest
from spectraven.checks import SSHCheck, HTTPCheck, TelnetCheck

class TestSecurityChecks(unittest.TestCase):
    def setUp(self):
        self.ssh_check = SSHCheck()
        self.http_check = HTTPCheck()
        self.telnet_check = TelnetCheck()
    
    def test_ssh_version_check(self):
        # Test SSH-1 detection
        result = self.ssh_check.check('127.0.0.1', 22, 'SSH-1.99-OpenSSH_1.0')
        self.assertFalse(result['passed'])
        self.assertEqual(result['severity'], 'high')
    
    def test_telnet_check(self):
        # Telnet should always fail security check
        result = self.telnet_check.check('127.0.0.1', 23, 'Telnet service')
        self.assertFalse(result['passed'])
        self.assertEqual(result['severity'], 'high')