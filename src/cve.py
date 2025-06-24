# spectraven/cve.py
import json
import requests
import re
from datetime import datetime

class CVELookup:
    def __init__(self):
        self.cve_cache = {}
        self.api_url = "https://cve.circl.lu/api/search"
    
    def lookup_cves(self, banner):
        """Look up CVEs based on service banner"""
        if not banner or banner.startswith('Error'):
            return []
        
        # Extract service information from banner
        service_info = self._parse_banner(banner)
        if not service_info:
            return []
        
        cves = []
        
        # Check local database first
        local_cves = self._check_local_cves(service_info)
        cves.extend(local_cves)
        
        # Check online API (with rate limiting)
        try:
            online_cves = self._check_online_cves(service_info)
            cves.extend(online_cves)
        except:
            pass  # Fail silently if API is unavailable
        
        return cves[:10]  # Limit to top 10 CVEs
    
    def _parse_banner(self, banner):
        """Parse banner to extract service name and version"""
        patterns = [
            r'Apache/([0-9]+\.[0-9]+\.[0-9]+)',
            r'nginx/([0-9]+\.[0-9]+\.[0-9]+)',
            r'OpenSSH_([0-9]+\.[0-9]+)',
            r'Microsoft-IIS/([0-9]+\.[0-9]+)',
            r'vsftpd ([0-9]+\.[0-9]+\.[0-9]+)',
            r'ProFTPD ([0-9]+\.[0-9]+\.[0-9]+)',
            r'Postfix ([0-9]+\.[0-9]+\.[0-9]+)',
            r'Exim ([0-9]+\.[0-9]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service = pattern.split('/')[0].replace('([0-9]+\\.[0-9]+\\.[0-9]+)', '').replace('([0-9]+\\.[0-9]+)', '')
                service = service.replace('_', '').replace('\\', '')
                version = match.group(1)
                return {'service': service, 'version': version}
        
        return None
    
    def _check_local_cves(self, service_info):
        """Check against local CVE database"""
        # Sample local CVE data (in real implementation, this would be a proper database)
        local_cves = {
            'Apache': {
                '2.2.22': [
                    {
                        'id': 'CVE-2012-0053',
                        'description': 'Apache HTTP Server 2.2.22 allows remote attackers to obtain sensitive information',
                        'severity': 'medium',
                        'cvss': 5.0
                    }
                ],
                '2.4.7': [
                    {
                        'id': 'CVE-2014-0098',
                        'description': 'Apache HTTP Server 2.4.7 mod_log_config module denial of service',
                        'severity': 'medium',
                        'cvss': 4.3
                    }
                ]
            },
            'OpenSSH': {
                '6.6': [
                    {
                        'id': 'CVE-2014-2653',
                        'description': 'OpenSSH 6.6 allows remote attackers to cause denial of service',
                        'severity': 'medium',
                        'cvss': 5.0
                    }
                ]
            },
            'nginx': {
                '1.4.0': [
                    {
                        'id': 'CVE-2013-2028',
                        'description': 'nginx 1.4.0 allows remote attackers to bypass access restrictions',
                        'severity': 'medium',
                        'cvss': 4.3
                    }
                ]
            }
        }
        
        service = service_info['service']
        version = service_info['version']
        
        return local_cves.get(service, {}).get(version, [])
    
    def _check_online_cves(self, service_info):
        """Check online CVE database"""
        try:
            search_term = f"{service_info['service']} {service_info['version']}"
            
            # Simple mock implementation - in reality, you'd use a proper API
            # This is a placeholder to show the structure
            return []
        except:
            return []