import os
import sys
import subprocess
import time
import itertools
import re
from rich.console import Console
from pyfiglet import Figlet
from threading import Thread

# Function to print the banner
def print_banner():
    fig = Figlet(font="slant")
    banner = fig.renderText("genMAP")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold green]GenMAP: Automating Nmap Scans with Ease[/bold green]")
    console.print("[yellow]Created by: K3strelSec | Version: 1.0.0[/yellow]")
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

# Spinner for showing scan progress
def spinner():
    sys.stdout.write("\rScanning... ")
    sys.stdout.flush()
    
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if not scanning:
            sys.stdout.write("\r\033[K")  # Clears the entire line
            sys.stdout.flush()
            break
        sys.stdout.write(f"\rScanning... {c}   ")  # Ensures spacing
        sys.stdout.flush()
        time.sleep(0.1)
    
    sys.stdout.write("\rScanning complete.      \n")  # Clears after finishing
    sys.stdout.flush()

# Function to colorize Nmap output based on patterns
def colorize_output(output):
    # Regex patterns to match different sections
    patterns = {
        "open_ports": r"(\d+/tcp|udp)\s+open",  # Matches open ports
        "service_info": r"Service Info",  # Matches service info
        "os_details": r"OS details",  # Matches OS details
        "vulnerabilities": r"vuln",  # Matches vulnerabilities
        "active_directory": r"(Active Directory|Domain)",  # Matches AD/Domain info
    }

    # Apply color based on matched patterns
    colored_output = output
    colored_output = re.sub(patterns["open_ports"], lambda x: f"[red]{x.group()}[/red]", colored_output)
    colored_output = re.sub(patterns["service_info"], lambda x: f"[blue]{x.group()}[/blue]", colored_output)
    colored_output = re.sub(patterns["os_details"], lambda x: f"[green]{x.group()}[/green]", colored_output)
    colored_output = re.sub(patterns["vulnerabilities"], lambda x: f"[yellow]{x.group()}[/yellow]", colored_output)
    colored_output = re.sub(patterns["active_directory"], lambda x: f"[purple]{x.group()}[/purple]", colored_output)

    # Return the colorized output
    return colored_output

# Function to get scan mode from the user
def get_scan_mode():
    console.print("[bold cyan]Select scan mode:[/bold cyan]")
    console.print("1. [yellow]CTF Mode[/yellow] - Aggressive scanning")
    console.print("2. [yellow]Pentest Mode[/yellow] - Stealth scanning")
    mode = input("Enter 1 for CTF Mode or 2 for Pentest Mode: ")
    if mode == "1":
        return "ctf"
    elif mode == "2":
        return "pentest"
    else:
        console.print("[red]Invalid choice! Defaulting to CTF mode.[/red]")
        return "ctf"

# Function to get target IP/domain from the user
def get_target():
    target = input("Enter the target IP or domain to scan: ")
    return target

# Function to save the scan results to a file
def save_scan_results(target, output):
    scan_count = 1
    while os.path.exists(f"zenmap_{scan_count}.txt"):
        scan_count += 1
    filename = f"zenmap_{scan_count}.txt"
    with open(filename, "a") as f:
        f.write(f"\n=== Scan Results for {target} ===\n")
        f.write(output + "\n")

# Function to run the Nmap scan
def run_nmap_scan(target, mode, sudo_password):
    global scanning
    scanning = True
    
    console.print(f"\n[bold green]Running Nmap scans on {target} in {mode.upper()} mode...[/bold green]")
    
    time.sleep(1)  # Allow time before spinner starts
    spin_thread = Thread(target=spinner, daemon=True)
    spin_thread.start()
    
    scan_cmds = {
        "ctf": [
            ["sudo", "nmap", "-A", "-T4", "-p-", "--script=vuln,auth,default", target],
            ["sudo", "nmap", "-sC", "-sV", "-O", "-p-", "--script=banner,http-title", target],
            ["sudo", "nmap", "-sU", "-T4", "-p-", target],
        ],
        "pentest": [
            ["sudo", "nmap", "-sS", "-T2", "-Pn", "-f", "-D", "RND:10", "--script=smb-enum-shares,smb-os-discovery", target],
            ["sudo", "nmap", "-sU", "-T2", "-Pn", "-f", target],
        ]
    }
    
    for cmd in scan_cmds[mode]:
        result = subprocess.run(cmd, capture_output=True, text=True, input=sudo_password)
        colorized_output = colorize_output(result.stdout)  # Apply the colorization
        console.print(f"[white]{colorized_output}[/white]")  # Print the colored output

    scanning = False
    spin_thread.join()

# Function to prompt for sudo password (asked only once)
def get_sudo_password():
    console.print("[yellow]Please enter your sudo password to start scanning.[/yellow]")
    sudo_password = input("Password: ")
    return sudo_password

# Main function to execute the script
def main():
    print_banner()
    global target
    mode = get_scan_mode()
    sudo_password = get_sudo_password()  # Ask for sudo password once before scanning starts
    target = get_target()
    run_nmap_scan(target, mode, sudo_password)  # Pass the sudo password for all nmap scans

if __name__ == "__main__":
    console = Console()
    scanning = False
    main()
