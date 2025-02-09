import os
import sys
import subprocess
import re
import json
import getpass
from datetime import datetime
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
    console.print("[yellow]Created by: K3strelSec | Version: 2.2.5[/yellow]")
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

# ✅ **Colorization Function**
def colorize_output(output):
    patterns = {
        "open_ports": r"(\d+)/(tcp|udp)\s+open",
        "service_info": r"(Service Info:.*|http-server-header:.*|http-title:.*)",
        "os_details": r"(OS details|Running|CPE:.*): (.+)",
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

# ✅ **Restored `parse_results` Function**
def parse_results(output):
    open_ports = re.findall(r"(\d+)/(tcp|udp)\s+open", output)
    vulnerabilities = list(set(re.findall(r"CVE-\d{4}-\d+", output)))  # Remove duplicates

    os_details = re.search(r"(OS details|Running): (.+)", output)
    os_cpe = re.search(r"CPE: (cpe:/o:[a-z]+:[a-z_]+)", output)
    os_details = os_details.group(2) if os_details else os_cpe.group(1) if os_cpe else "Unknown OS"

    service_info = list(set(re.findall(r"(Service Info: .+|http-server-header: .+|http-title: .+)", output)))

    active_directory = list(set(re.findall(r"(Active Directory|Domain Controller|Kerberos|SMB|LDAP|FQDN)", output)))

    general_info = []
    indicators = {
        "File Exposure": [r"(index of /|directory listing|filetype|file)"],
        "Credentials": [r"(password|username|credentials|hash|login)"],
        "Sensitive Files": [r"(robots.txt|sitemap.xml|exposed|backup|config|db)"],
        "Internal IPs": [r"(\d+\.\d+\.\d+\.\d+)"],
        "Web Tech": [r"(PHP|WordPress|Drupal|Joomla|Apache)"],
        "Miscellaneous": [r"(Public Key|Certificate|TLS|SSL|DNS)"]
    }

    for category, patterns in indicators.items():
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                general_info.append(f"{category}: {', '.join(set(matches))}")

    console.print("\n[bold cyan]Parsed Data:[/bold cyan]")
    console.print(f"[red]Open Ports:[/red] {', '.join([p[0] for p in open_ports]) if open_ports else 'None'}")
    console.print(f"[green]OS Details:[/green] {os_details}")
    console.print(f"[blue]Service Info:[/blue] {', '.join(service_info) if service_info else 'None'}")
    console.print(f"[purple]Active Directory:[/purple] {', '.join(active_directory) if active_directory else 'None'}")
    console.print(f"[yellow]Vulnerabilities:[/yellow] {', '.join(vulnerabilities) if vulnerabilities else 'None'}")
    console.print(f"[white]General:[/white] {', '.join(general_info) if general_info else 'None'}")

    return open_ports, vulnerabilities, os_details, service_info, active_directory, general_info

# ✅ **Restored `generate_exploitation_tips` Function**
def generate_exploitation_tips(open_ports, vulnerabilities, general_info):
    recommendations = []

    # Exploit Suggestions for Common Services
    attack_methods = {
        21: "FTP detected. Try `ftp <ip>`, anonymous login, brute-force (`hydra`).",
        22: "SSH detected. Try key-based attacks, brute-force (`hydra`, `patator`).",
        25: "SMTP detected. Check for Open Relay (`Metasploit smtp_version`).",
        53: "DNS detected. Try zone transfer (`dig axfr @<ip>`), enumerate subdomains (`dnsenum`).",
        80: "HTTP detected. Run `gobuster`, check for SQL Injection, LFI, RCE (`sqlmap`).",
        443: "HTTPS detected. Look for SSL vulnerabilities (`sslscan`, `testssl.sh`).",
        3306: "MySQL detected. Try `mysql -u root -h <ip>`, check for weak credentials.",
        3389: "RDP detected. Try brute-force (`xfreerdp`), exploit (`BlueKeep`)."
    }

    for port, protocol in open_ports:
        port = int(port)
        if port in attack_methods:
            recommendations.append(attack_methods[port])

    for vuln in vulnerabilities:
        recommendations.append(f"Possible exploit available for `{vuln}`. Check ExploitDB: https://www.exploit-db.com/search?cve={vuln}")

    console.print("\n[bold cyan]Exploitation Recommendations:[/bold cyan]")
    for rec in recommendations:
        console.print(f"[bold yellow]- {rec}[/bold yellow]")

    return recommendations

# ✅ **Function to Run the Nmap Scan**
def run_scan(target):
    global sudo_password
    if not sudo_password:
        console.print("\n[bold yellow]Please enter your sudo password for this scan:[/bold yellow]")
        sudo_password = getpass.getpass("Sudo Password: ")

    cmd = ["nmap", "-sS", "-sU", "-sC", "-sV", "-O", "-p-", "-T4", "--top-ports", "200",
           "--script=vuln,vulners,http-enum,smb-enum-shares,rdp-enum-encryption", target]

    console.print(f"\n[bold green]Running Optimized Nmap Scan (TCP + UDP): {' '.join(cmd)}[/bold green]")

    full_cmd = ["sudo", "-S"] + cmd

    try:
        process = subprocess.Popen(
            full_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        process.stdin.write(sudo_password + "\n")
        process.stdin.flush()

        output_lines = []
        for line in iter(process.stdout.readline, ''):
            if not line.startswith("Starting Nmap"):  
                output_lines.append(line)

        process.stdout.close()
        process.wait()

        output = "".join(output_lines)
        console.print("\n[bold white]Raw Data:[/bold white]")
        console.print(colorize_output(output))

        open_ports, vulnerabilities, os_details, service_info, active_directory, general_info = parse_results(output)
        generate_exploitation_tips(open_ports, vulnerabilities, general_info)

    except Exception as e:
        console.print(f"[bold red]Error running scan: {e}[/bold red]")

# ✅ **Final Fix**
def main():
    print_banner()
    target = console.input("[bold yellow]Enter Target IP or domain: [/bold yellow]").strip()
    run_scan(target)

if __name__ == "__main__":
    main()
