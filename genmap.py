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

# **Timestamped File Naming**
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# **Print the Banner**
def print_banner():
    fig = Figlet(font="slant")
    banner = fig.renderText("genMAP")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold green]GenMAP: Automating Nmap Scans with Ease[/bold green]")
    console.print(f"[yellow]Created by: K3strelSec | Version: 2.3.1 (Secondary Vulnerability Scan Fixed!)[/yellow]")
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

# **Colorization Function**
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

# **Fixed `save_results()` to Accept 3 Arguments**
def save_results(target, output, scan_type):
    timestamp = get_timestamp()
    filename = f"genMAP_{scan_type}_scan_{target}_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(output)
    console.print(f"\n[bold cyan]Scan saved to: {filename}[/bold cyan]")
    
    # Define `parse_results()` before using it
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

# **Fully Expanded attack_methods**
def generate_exploitation_tips(open_ports, vulnerabilities, general_info):
    recommendations = []

    attack_methods = {
        21: "FTP detected. Try `ftp <ip>`, anonymous login, brute-force (`hydra`).",
        22: "SSH detected. Try key-based attacks, brute-force (`hydra`, `patator`).",
        23: "Telnet detected. Try weak credentials, sniffing (`tcpdump`), MITM attacks.",
        25: "SMTP detected. Check for Open Relay (`Metasploit smtp_version`).",
        53: "DNS detected. Try zone transfer (`dig axfr @<ip>`), enumerate subdomains (`dnsenum`).",
        67: "DHCP detected. Rogue DHCP possible (`dhcpstarv`).",
        69: "TFTP detected. Check for open directory listing (`tftp <ip>`).",
        80: "HTTP detected. Run `gobuster`, check for SQL Injection, LFI, RCE (`sqlmap`).",
        110: "POP3 detected. Try brute-force (`hydra`).",
        111: "RPCBind detected. Try `rpcinfo -p <ip>`, `showmount -e <ip>`.",
        119: "NNTP (Usenet) detected. Try authentication bypass (`telnet <ip> 119`).",
        123: "NTP detected. Check for amplification attack (`ntpq -c rv <ip>`).",
        135: "MSRPC detected. Use `rpcdump.py` from Impacket.",
        137: "NetBIOS detected. Try `nmblookup -A <ip>` to list NetBIOS names.",
        139: "SMB detected. Check for anonymous login, null sessions (`enum4linux`, `smbclient`).",
        143: "IMAP detected. Try brute-force (`hydra`), inspect emails.",
        161: "SNMP detected. Try `snmpwalk -v1 -c public <ip>` for enumeration.",
        389: "LDAP detected. Try anonymous bind (`ldapsearch -x -h <ip>`).",
        443: "HTTPS detected. Look for SSL vulnerabilities (`sslscan`, `testssl.sh`).",
        445: "SMB detected. Test for EternalBlue (`Metasploit ms17_010`), password spray.",
        512: "Rexec detected. Try `rsh <ip>`, check `.rhosts` files.",
        513: "Rlogin detected. Try `.rhosts` trust abuse.",
        514: "Rsh detected. Possible remote command execution.",
        873: "RSYNC detected. Check for open directory (`rsync --list-only <ip>::`).",
        902: "VMware detected. Check for guest-to-host escape exploits.",
        1080: "SOCKS proxy detected. Possible open relay attack.",
        1433: "MSSQL detected. Try default credentials (`sa` user), enumerate databases (`nmap --script ms-sql*`).",
        1521: "Oracle DB detected. Try `odat.py` for database attacks.",
        1723: "PPTP VPN detected. Check for MS-CHAPv2 vulnerabilities.",
        2049: "NFS detected. Try `showmount -e <ip>` to list shares.",
        2181: "Zookeeper detected. Try `echo srvr | nc <ip> 2181`.",
        2375: "Docker API detected. Check for unauthenticated access (`curl http://<ip>:2375/version`).",
        3306: "MySQL detected. Try `mysql -u root -h <ip>`, check for weak credentials.",
        3389: "RDP detected. Try brute-force (`xfreerdp`), exploit (`BlueKeep`).",
        3632: "DistCC detected. Try remote command execution (`nmap --script distcc-cve2004-2687`).",
        4444: "Metasploit detected. Possible Meterpreter shell running (`nc -nv <ip> 4444`).",
        5000: "Docker Registry detected. Check for open access (`curl -X GET http://<ip>:5000/v2/_catalog`).",
        5432: "PostgreSQL detected. Try `psql -h <ip> -U postgres`, check for weak passwords.",
        5900: "VNC detected. Try password cracking (`hydra -P rockyou.txt -t 4 -s 5900 <ip> vnc`).",
        5985: "WinRM detected. Check for admin access (`evil-winrm -i <ip> -u <user> -p <password>`).",
        6379: "Redis detected. Check for unauthenticated access (`redis-cli -h <ip> ping`).",
        6667: "IRC detected. Check for open proxy (`nmap --script irc-unrealircd-backdoor`).",
        7001: "WebLogic detected. Check for deserialization vulnerabilities.",
        8000: "Common Web App detected. Run `gobuster`, check for admin panels.",
        8080: "Common Proxy/Web App detected. Test for open proxy abuse.",
        8443: "Alternative HTTPS detected. Look for misconfigurations.",
        8888: "Jupyter Notebook detected. Check for open access (`http://<ip>:8888/tree`).",
        9000: "PHP-FPM detected. Possible remote code execution (`CVE-2019-11043`).",
        9200: "Elasticsearch detected. Check for unauthenticated API access (`curl -X GET <ip>:9200/_cluster/health`).",
        11211: "Memcached detected. Try amplification attacks (`memcrashed`).",
        27017: "MongoDB detected. Try `mongo --host <ip>` to check for unauthenticated access.",
        50000: "SAP Management Console detected. Check for vulnerabilities (`nmap --script sap* -p 50000 <ip>`).",
    }

    # Check if open ports have known exploits
    for port, protocol in open_ports:
        port = int(port)
        if port in attack_methods:
            recommendations.append(attack_methods[port])

    # Check for CVE vulnerabilities found in the scan
    for vuln in vulnerabilities:
        recommendations.append(f"Possible exploit available for `{vuln}`. Check ExploitDB: https://www.exploit-db.com/search?cve={vuln}")

    # **Print Exploitation Recommendations**
    console.print("\n[bold cyan]Exploitation Recommendations:[/bold cyan]")
    for rec in recommendations:
        console.print(f"[bold yellow]- {rec}[/bold yellow]")

    return recommendations

# **Run the First TCP Scan**
def run_tcp_scan(target):
    global sudo_password
    if not sudo_password:
        console.print("\n[bold yellow]Please enter your sudo password for this scan:[/bold yellow]")
        sudo_password = getpass.getpass("Sudo Password: ")

    cmd = ["nmap", "-sS", "-p-", "-T4", "-O", "-sV", "-sC", target]  # TCP SYN scan first
    console.print(f"\n[bold green]Running TCP Scan: {' '.join(cmd)}[/bold green]")

    process = subprocess.Popen(["sudo", "-S"] + cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    process.stdin.write(sudo_password + "\n")
    process.stdin.flush()

    output_lines = []
    for line in iter(process.stdout.readline, ''):
        output_lines.append(line)

    process.stdout.close()
    process.wait()
    output = "".join(output_lines)

    console.print("\n[bold blue]Raw Data (TCP Scan Output):[/bold blue]")
    console.print(colorize_output(output))

    save_results(target, output, "tcp")
    open_ports, vulnerabilities, os_details, service_info, active_directory, general_info = parse_results(output)

    # Extract TCP ports found
    discovered_ports = ",".join([p[0] for p in open_ports])
    console.print(f"[bold cyan]Detected TCP Ports: {discovered_ports}[/bold cyan]")

    # **Proceed to UDP Scan**
    run_udp_scan(target, discovered_ports)

# **Run the Second UDP Scan**
def run_udp_scan(target, discovered_ports):
    console.print("\n[bold yellow]Running UDP Scan...[/bold yellow]")

    cmd = ["nmap", "-sU", "--top-ports", "200", "-T4", target]  # Scan only top 100 UDP ports
    console.print(f"\n[bold green]Running UDP Scan: {' '.join(cmd)}[/bold green]")

    process = subprocess.Popen(["sudo", "-S"] + cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    process.stdin.write(sudo_password + "\n")
    process.stdin.flush()

    output_lines = []
    for line in iter(process.stdout.readline, ''):
        output_lines.append(line)

    process.stdout.close()
    process.wait()
    output = "".join(output_lines)

    console.print("\n[bold blue]Raw Data (UDP Scan Output):[/bold blue]")
    console.print(colorize_output(output))

    save_results(target, output, "udp")
    open_ports, vulnerabilities, os_details, service_info, active_directory, general_info = parse_results(output)

    # **Proceed to Vulnerability Scan**
    run_vuln_scan(target, discovered_ports)

# **Run the Final Vulnerability Scan**
def run_vuln_scan(target, discovered_ports):
    console.print("\n[bold yellow]Running Final Vulnerability Scan...[/bold yellow]")

    cmd = ["nmap", "-sV", "--script=vuln,vulners,http-enum,smb-enum-shares,rdp-enum-encryption", "-p", discovered_ports, target]
    console.print(f"\n[bold green]Running Vulnerability Scan: {' '.join(cmd)}[/bold green]")

    process = subprocess.Popen(["sudo", "-S"] + cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    process.stdin.write(sudo_password + "\n")
    process.stdin.flush()

    output_lines = []
    for line in iter(process.stdout.readline, ''):
        output_lines.append(line)

    process.stdout.close()
    process.wait()
    output = "".join(output_lines)

    console.print("\n[bold blue]Raw Data (Vulnerability Scan Output):[/bold blue]")
    console.print(colorize_output(output))

    save_results(target, output, "vuln")
    open_ports, vulnerabilities, os_details, service_info, active_directory, general_info = parse_results(output)
    generate_exploitation_tips(open_ports, vulnerabilities, general_info)

# **Main Function (Starts TCP First)**
def main():
    print_banner()
    target = console.input("[bold yellow]Enter Target IP or domain: [/bold yellow]").strip()
    run_tcp_scan(target)

if __name__ == "__main__":
    main()

