import os
import sys
import subprocess
import re
import getpass
from rich.console import Console
from pyfiglet import Figlet

# Initialize console
console = Console()
sudo_password = None

# Function to print the banner
def print_banner():
    fig = Figlet(font="slant")
    banner = fig.renderText("genMAP")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold green]GenMAP: Automating Nmap Scans with Ease[/bold green]")
    console.print("[yellow]Created by: K3strelSec | Version: 1.5.0[/yellow]")
    console.print("[bold bright_red]---------------------------------------------------[/bold bright_red]")
    console.print("[bold cyan]Key:")
    console.print("[red]Red - Open Ports[/red]")
    console.print("[blue]Blue - Service Information[/blue]")
    console.print("[green]Green - OS Details[/green]")
    console.print("[yellow]Yellow - Vulnerabilities[/yellow]")
    console.print("[white]White - General Info[/white]")
    console.print("[purple]Purple - Active Directory / Domain Info[/purple]")
    console.print("")
    console.print("[bold bright_magenta]---------------------------------------------------[/bold bright_magenta]")

# Function to run a single scan command
def run_scan(target):
    global sudo_password
    if not sudo_password:
        console.print("\n[bold yellow]Please enter your sudo password for this scan:[/bold yellow]")
        sudo_password = getpass.getpass("Sudo Password: ")

    cmd = ["nmap", "-sC", "-sV", "-O", "-p-", "--script=vuln,vulners", target]
    console.print(f"\n[bold green]Running Nmap scan: {' '.join(cmd)}[/bold green]")

    full_cmd = ["sudo", "-S"] + cmd

    try:
        process = subprocess.Popen(
            full_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        process.stdin.write(sudo_password + "\n")
        process.stdin.flush()

        output_lines = []
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(line)
            sys.stdout.flush()
            output_lines.append(line)

        process.stdout.close()
        process.wait()

        output = "".join(output_lines)
        console.print("\n[bold white]Raw Data:[/bold white]")
        console.print("[bold bright_magenta]---------------------------------------------------[/bold bright_magenta]")
        console.print(colorize_output(output))
        console.print("[bold bright_magenta]---------------------------------------------------[/bold bright_magenta]")

        parse_results(output)

    except Exception as e:
        console.print(f"[bold red]Error running scan: {e}[/bold red]")

# Function to colorize Nmap output
def colorize_output(output):
    patterns = {
        "open_ports": r"(\d+)/(tcp|udp)\s+open",
        "service_info": r"(Service Info:.*|http-server-header:.*|http-title:.*)",
        "os_details": r"(OS details|Operating System|Kernel version|Windows version): (.+)",
        "vulnerabilities": r"(CVE-\d{4}-\d+|exploit|vuln|potentially vulnerable)",
        "active_directory": r"(Active Directory|Domain Controller|Kerberos|SMB|LDAP|FQDN)"
    }
    for key, pattern in patterns.items():
        color = {
            "open_ports": "red", "service_info": "blue", "os_details": "green",
            "vulnerabilities": "yellow", "active_directory": "purple"
        }[key]
        output = re.sub(pattern, lambda x: f"[{color}]{x.group()}[/{color}]", output)
    return output

# Function to parse scan results
def parse_results(output):
    open_ports = re.findall(r"(\d+)/(tcp|udp)\s+open", output)
    service_info = re.search(r"Service Info: (.*)", output)
    os_details = re.search(r"OS details: (.*)", output)
    vulnerabilities = re.findall(r"CVE-\d{4}-\d+", output)

    general_info = []
    indicators = {
        "File Exposure": [r"(index of /|directory listing|filetype|file)"],
        "Credentials": [r"(password|username|credentials|hash|login)"],
        "HTTP/Sensitive Information": [r"(robots.txt|sitemap.xml|exposed)"],
        "Network Infrastructure": [r"(Proxy|Firewall|VPN|Load Balancer)"],
        "Authentication Methods": [r"(NTLM|Kerberos|Basic Auth|Digest Auth)"],
        "Internal IPs or Hosts": [r"(\d+\.\d+\.\d+\.\d+)"],
        "Web Technologies": [r"(PHP|WordPress|Drupal|Joomla|Apache)"],
        "Potential Data Leaks": [r"(config|backup|DB|dump|leak)"],
        "Miscellaneous Recon Info": [r"(Public Key|Certificate|TLS|SSL|DNS)"],
        "File Listings": [r"(\d+)\s+(\d{2}-\w{3}-\d{4} \d{2}:\d{2})\s+(.+)"]
    }

    for category, patterns in indicators.items():
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                if category == "File Listings":
                    for size, date, filename in matches:
                        general_info.append(f"File: {filename} ({size} bytes, {date})")
                else:
                    general_info.append(f"{category}: {', '.join(set(matches))}")

    console.print("\n[bold cyan]Parsed Data:[/bold cyan]")
    console.print(f"[red]Open Ports:[/red] {', '.join([p[0] for p in open_ports]) if open_ports else 'None'}")
    console.print(f"[blue]Service Info:[/blue] {service_info.group(1) if service_info else 'None'}")
    console.print(f"[green]OS Details:[/green] {os_details.group(1) if os_details else 'None'}")
    console.print(f"[yellow]Vulnerabilities:[/yellow] {', '.join(vulnerabilities) if vulnerabilities else 'None'}")
    console.print(f"[white]General:[/white] {', '.join(general_info) if general_info else 'None'}")

# Main function
def main():
    print_banner()
    target = console.input("[bold yellow]Enter Target IP or domain: [/bold yellow]").strip()
    run_scan(target)

if __name__ == "__main__":
    main()
