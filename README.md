# SpectRaven Network Security Scanner

SpectRaven is a comprehensive network security scanner that performs host discovery, port scanning, banner grabbing, security checks, and vulnerability assessment.

## Features

- **Host Discovery**: ARP scanning and ping sweeps
- **Port Scanning**: TCP connect and SYN scanning
- **Banner Grabbing**: Service identification and version detection
- **Security Checks**: Automated security misconfiguration detection
- **CVE Lookup**: Vulnerability database integration
- **Reporting**: HTML and PDF report generation
- **Plugin System**: Extensible architecture for custom checks

## Installation

```bash
git clone https://github.com/yourusername/SpectRaven.git
cd SpectRaven
pip install -r requirements.txt
```

## Usage

### Host Discovery
```bash
python -m spectraven discover --network 192.168.1.0/24
```

### Full Network Scan
```bash
python -m spectraven scan --network 192.168.1.0/24 --ports 22,80,443 --output results.json
```

### Generate Report
```bash
python -m spectraven report --input results.json --output report.html
```

## Security Checks

SpectRaven includes built-in security checks for:
- SSH version and configuration
- HTTP security headers
- FTP anonymous access
- SMTP open relay
- Telnet service detection
- And more...

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning networks.
