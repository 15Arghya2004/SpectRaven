# spectraven/checks/__init__.py
import os
import importlib
import inspect
from abc import ABC, abstractmethod

class BaseCheck(ABC):
    """Base class for security checks"""
    
    @abstractmethod
    def check(self, host, port, banner):
        """
        Perform security check
        Returns: dict with 'passed', 'name', 'details', 'severity'
        """
        pass

class CheckManager:
    def __init__(self):
        self.checks = []
        self._load_checks()
    
    def _load_checks(self):
        """Load all check modules from checks directory"""
        checks_dir = os.path.dirname(__file__)
        
        # Built-in checks
        self.checks.extend([
            SSHCheck(),
            HTTPCheck(),
            FTPCheck(),
            SMTPCheck(),
            TelnetCheck()
        ])
    
    def run_checks(self, host, port, banner):
        """Run all applicable checks for a service"""
        results = []
        
        for check in self.checks:
            try:
                result = check.check(host, port, banner)
                if result:
                    results.append(result)
            except Exception as e:
                results.append({
                    'passed': False,
                    'name': f'{check.__class__.__name__} Error',
                    'details': str(e),
                    'severity': 'low'
                })
        
        return results

class SSHCheck(BaseCheck):
    def check(self, host, port, banner):
        if port != 22 and 'SSH' not in banner.upper():
            return None
        
        checks = []
        
        # Check for old SSH version
        if 'SSH-1' in banner:
            checks.append({
                'passed': False,
                'name': 'SSH Version 1',
                'details': 'SSH version 1 is deprecated and insecure',
                'severity': 'high'
            })
        
        # Check for weak SSH versions
        if any(weak in banner for weak in ['OpenSSH_4', 'OpenSSH_5', 'OpenSSH_6.0', 'OpenSSH_6.1']):
            checks.append({
                'passed': False,
                'name': 'Outdated SSH Version',
                'details': f'SSH version appears outdated: {banner}',
                'severity': 'medium'
            })
        
        return checks[0] if checks else {
            'passed': True,
            'name': 'SSH Version Check',
            'details': 'SSH version appears current',
            'severity': 'info'
        }

class HTTPCheck(BaseCheck):
    def check(self, host, port, banner):
        if port not in [80, 443, 8080, 8443] and 'HTTP' not in banner.upper():
            return None
        
        import requests
        
        checks = []
        
        try:
            # Check for HTTPS
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{host}:{port}"
            
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME type sniffing protection missing',
                'X-XSS-Protection': 'XSS protection header missing',
                'Strict-Transport-Security': 'HSTS header missing (HTTPS only)',
                'Content-Security-Policy': 'CSP header missing'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    if header == 'Strict-Transport-Security' and protocol == 'http':
                        continue  # Skip HSTS check for HTTP
                    
                    checks.append({
                        'passed': False,
                        'name': f'Missing {header}',
                        'details': description,
                        'severity': 'medium'
                    })
            
            # Check for server disclosure
            if 'Server' in headers:
                server = headers['Server']
                if any(pattern in server.lower() for pattern in ['apache/2.2', 'nginx/1.0', 'iis/6.0']):
                    checks.append({
                        'passed': False,
                        'name': 'Server Version Disclosure',
                        'details': f'Server header reveals potentially outdated version: {server}',
                        'severity': 'low'
                    })
            
        except Exception as e:
            checks.append({
                'passed': False,
                'name': 'HTTP Check Error',
                'details': f'Could not perform HTTP checks: {str(e)}',
                'severity': 'low'
            })
        
        return checks[0] if checks else {
            'passed': True,
            'name': 'HTTP Security Check',
            'details': 'Basic HTTP security checks passed',
            'severity': 'info'
        }

class FTPCheck(BaseCheck):
    def check(self, host, port, banner):
        if port != 21 and 'FTP' not in banner.upper():
            return None
        
        # Check for anonymous FTP
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login('anonymous', 'anonymous@example.com')
            ftp.quit()
            
            return {
                'passed': False,
                'name': 'Anonymous FTP Access',
                'details': 'FTP server allows anonymous access',
                'severity': 'medium'
            }
        except:
            return {
                'passed': True,
                'name': 'Anonymous FTP Check',
                'details': 'Anonymous FTP access denied',
                'severity': 'info'
            }

class SMTPCheck(BaseCheck):
    def check(self, host, port, banner):
        if port not in [25, 465, 587] and 'SMTP' not in banner.upper():
            return None
        
        # Check for SMTP relay
        try:
            import smtplib
            smtp = smtplib.SMTP(host, port, timeout=5)
            smtp.helo('test.com')
            
            # Try to send test email
            try:
                smtp.mail('test@test.com')
                smtp.rcpt('test@external.com')
                smtp.quit()
                
                return {
                    'passed': False,
                    'name': 'Open SMTP Relay',
                    'details': 'SMTP server appears to be an open relay',
                    'severity': 'high'
                }
            except:
                smtp.quit()
                return {
                    'passed': True,
                    'name': 'SMTP Relay Check',
                    'details': 'SMTP relay properly configured',
                    'severity': 'info'
                }
        except:
            return {
                'passed': False,
                'name': 'SMTP Check Error',
                'details': 'Could not connect to SMTP service',
                'severity': 'low'
            }

class TelnetCheck(BaseCheck):
    def check(self, host, port, banner):
        if port != 23 and 'TELNET' not in banner.upper():
            return None
        
        return {
            'passed': False,
            'name': 'Telnet Service',
            'details': 'Telnet service is inherently insecure (unencrypted)',
            'severity': 'high'
        }