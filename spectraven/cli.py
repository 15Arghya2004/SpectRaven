#!/usr/bin/env python3
"""
SpectRaven CLI Interface
"""

import click
import json
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Handle relative imports properly
try:
    from .discovery import NetworkDiscovery
    from .scanner import PortScanner
    from .banner import BannerGrabber
    from .checks import CheckManager
    from .cve import CVELookup
    from .report import ReportGenerator
except ImportError:
    # Fallback for direct execution
    from discovery import NetworkDiscovery
    from scanner import PortScanner
    from banner import BannerGrabber
    from checks import CheckManager
    from cve import CVELookup
    from report import ReportGenerator

console = Console()

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """SpectRaven - Network Security Scanner"""
    pass

@cli.command()
@click.option('--network', '-n', required=True, help='Network range (e.g., 192.168.1.0/24)')
@click.option('--timeout', '-t', default=3, help='Timeout in seconds')
@click.option('--threads', default=20, help='Number of threads')
@click.option('--method', '-m', default='ping', type=click.Choice(['ping', 'tcp', 'both']), help='Discovery method')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def discover(network, timeout, threads, method, verbose):
    """Discover live hosts on network"""
    console.print(f"[bold blue]Discovering hosts on {network}[/bold blue]")
    console.print(f"[yellow]Method: {method}, Timeout: {timeout}s, Threads: {threads}[/yellow]")
    
    try:
        discovery = NetworkDiscovery(timeout=timeout, threads=threads)
        
        if method == 'ping':
            console.print("[cyan]Using ping sweep...[/cyan]")
            live_hosts = discovery.discover_hosts(network)
        elif method == 'tcp':
            console.print("[cyan]Using TCP ping on common ports...[/cyan]")
            live_hosts = discovery.discover_with_tcp_ping(network)
        else:  # both
            console.print("[cyan]Trying ping sweep first...[/cyan]")
            live_hosts = discovery.discover_hosts(network)
            if not live_hosts:
                console.print("[cyan]No results from ping, trying TCP ping...[/cyan]")
                live_hosts = discovery.discover_with_tcp_ping(network)
        
        if live_hosts:
            table = Table(title="Live Hosts")
            table.add_column("IP Address", style="cyan")
            table.add_column("Status", style="green")
            
            for host in live_hosts:
                table.add_row(host, "UP")
            
            console.print(table)
            console.print(f"[green]Found {len(live_hosts)} live hosts[/green]")
        else:
            console.print("[red]No live hosts found[/red]")
            console.print("[yellow]Try different methods:[/yellow]")
            console.print("  - Use --method tcp for TCP ping")
            console.print("  - Use --method both to try all methods")
            console.print("  - Increase --timeout value")
            console.print("  - Check if you're on the right network")
            
    except Exception as e:
        console.print(f"[red]Error during discovery: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())

@cli.command()
@click.option('--network', '-n', required=True, help='Network range or single IP')
@click.option('--ports', '-p', default='22,80,443,21,25,53,110,143,993,995', help='Ports to scan')
@click.option('--output', '-o', help='Output file (JSON)')
@click.option('--timeout', '-t', default=1, help='Timeout in seconds')
@click.option('--threads', default=50, help='Number of threads')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(network, ports, output, timeout, threads, verbose):
    """Full network scan with security checks"""
    console.print(f"[bold blue]Starting comprehensive scan of {network}[/bold blue]")
    
    try:
        # Parse ports
        port_list = [int(p.strip()) for p in ports.split(',')]
        
        # Discovery phase
        console.print("[yellow]Phase 1: Host Discovery[/yellow]")
        discovery = NetworkDiscovery(timeout=timeout, threads=threads)
        live_hosts = discovery.discover_hosts(network)
        
        if not live_hosts:
            console.print("[red]No live hosts found[/red]")
            return
        
        console.print(f"[green]Found {len(live_hosts)} live hosts[/green]")
        
        # Port scanning phase
        console.print("[yellow]Phase 2: Port Scanning[/yellow]")
        scanner = PortScanner(timeout=timeout, threads=threads)
        scan_results = {}
        
        with Progress() as progress:
            task = progress.add_task("Scanning ports...", total=len(live_hosts))
            for host in live_hosts:
                open_ports = scanner.scan_host(host, port_list)
                if open_ports:
                    scan_results[host] = open_ports
                progress.update(task, advance=1)
        
        # Banner grabbing phase
        console.print("[yellow]Phase 3: Banner Grabbing[/yellow]")
        banner_grabber = BannerGrabber(timeout=timeout)
        banner_results = {}
        
        for host, ports in scan_results.items():
            banner_results[host] = {}
            for port in ports:
                banner = banner_grabber.grab_banner(host, port)
                if banner:
                    banner_results[host][port] = banner
        
        # Security checks phase
        console.print("[yellow]Phase 4: Security Checks[/yellow]")
        check_manager = CheckManager()
        check_results = {}
        
        for host, ports in scan_results.items():
            check_results[host] = {}
            for port in ports:
                service_checks = check_manager.run_checks(host, port, banner_results.get(host, {}).get(port, ''))
                if service_checks:
                    check_results[host][port] = service_checks
        
        # CVE lookup phase
        console.print("[yellow]Phase 5: CVE Lookup[/yellow]")
        cve_lookup = CVELookup()
        cve_results = {}
        
        for host, ports in banner_results.items():
            cve_results[host] = {}
            for port, banner in ports.items():
                cves = cve_lookup.lookup_cves(banner)
                if cves:
                    cve_results[host][port] = cves
        
        # Compile final results
        final_results = {
            'scan_info': {
                'network': network,
                'ports_scanned': port_list,
                'live_hosts': len(live_hosts),
                'hosts_with_open_ports': len(scan_results)
            },
            'hosts': {}
        }
        
        for host in live_hosts:
            final_results['hosts'][host] = {
                'open_ports': scan_results.get(host, []),
                'banners': banner_results.get(host, {}),
                'security_checks': check_results.get(host, {}),
                'cves': cve_results.get(host, {})
            }
        
        # Display results
        console.print("\n[bold green]Scan Results[/bold green]")
        for host, data in final_results['hosts'].items():
            if data['open_ports']:
                console.print(f"\n[cyan]{host}[/cyan]")
                for port in data['open_ports']:
                    banner = data['banners'].get(port, 'Unknown')
                    console.print(f"  Port {port}: {banner}")
                    
                    # Show security issues
                    if port in data['security_checks']:
                        for check in data['security_checks'][port]:
                            if not check['passed']:
                                console.print(f"    [red]⚠ {check['name']}: {check['details']}[/red]")
                    
                    # Show CVEs
                    if port in data['cves']:
                        for cve in data['cves'][port]:
                            console.print(f"    [red]🔴 {cve['id']}: {cve['description'][:100]}...[/red]")
        
        # Save results
        if output:
            with open(output, 'w') as f:
                json.dump(final_results, f, indent=2)
            console.print(f"\n[green]Results saved to {output}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())

@cli.command()
@click.option('--input', '-i', required=True, help='Input JSON file')
@click.option('--output', '-o', required=True, help='Output HTML file')
@click.option('--format', default='html', help='Output format (html, pdf)')
def report(input, output, format):
    """Generate security report from scan results"""
    try:
        with open(input, 'r') as f:
            data = json.load(f)
        
        report_gen = ReportGenerator()
        
        if format == 'html':
            report_gen.generate_html_report(data, output)
        elif format == 'pdf':
            report_gen.generate_pdf_report(data, output)
        
        console.print(f"[green]Report generated: {output}[/green]")
        
    except FileNotFoundError:
        console.print(f"[red]Error: Input file {input} not found[/red]")
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")

if __name__ == '__main__':
    cli()