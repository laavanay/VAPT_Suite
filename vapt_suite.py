#!/usr/bin/env python3
"""
Mini VAPT Suite - Vulnerability Assessment and Penetration Testing Tool
Developed for educational purposes only. Use in a controlled lab environment.
"""

import socket
import subprocess
import sys
import os
import struct

# ─────────────────────────── COLORS ───────────────────────────
class Color:
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

# ─────────────────────────── BANNER ───────────────────────────
def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(f"""{Color.CYAN}{Color.BOLD}
  ╔══════════════════════════════════════════════════════════╗
  ║              Mini VAPT Suite v2.0                       ║
  ║   Vulnerability Assessment and Penetration Testing      ║
  ╠══════════════════════════════════════════════════════════╣
  ║  [i] Network Reconnaissance & Security Assessment Tool  ║
  ║  [i] Developed for Educational Purposes Only            ║
  ╚══════════════════════════════════════════════════════════╝
  {Color.RESET}
  {Color.YELLOW}[!] Disclaimer: This tool should only be used in a
      controlled lab environment (e.g., Kali Linux → Metasploitable).{Color.RESET}
""")

# ─────────────────────────── HELPERS ──────────────────────────
def info(msg):
    print(f"  {Color.CYAN}[i]{Color.RESET} {msg}")

def success(msg):
    print(f"  {Color.GREEN}[✓]{Color.RESET} {msg}")

def warning(msg):
    print(f"  {Color.YELLOW}[!]{Color.RESET} {msg}")

def error(msg):
    print(f"  {Color.RED}[✗]{Color.RESET} {msg}")

def section(title):
    print(f"\n  {Color.BOLD}{Color.BLUE}{'─'*56}")
    print(f"  {title}")
    print(f"  {'─'*56}{Color.RESET}\n")

def run_cmd(cmd):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=120
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[!] Command timed out."
    except Exception as e:
        return f"[!] Error: {e}"

def check_tool(tool_name):
    """Check if a command-line tool is available."""
    return subprocess.run(
        f"which {tool_name}", shell=True, capture_output=True
    ).returncode == 0

def resolve_target(target):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        error(f"Could not resolve hostname: {target}")
        return None

# ────────────────────── SCAN MODULES ──────────────────────────

def basic_info(target):
    """Module 1: Basic Information Gathering"""
    section("BASIC INFORMATION GATHERING")
    print(f"  {Color.GREEN}[+] Starting Mini VAPT Scan...{Color.RESET}")
    print(f"  {Color.GREEN}[+] Performing network reconnaissance...{Color.RESET}")
    print(f"  {Color.GREEN}[+] Target: {target}{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    info(f"Target     : {target}")
    info(f"IP Address : {ip}")

    # Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        info(f"Hostname   : {hostname}")
    except socket.herror:
        info("Hostname   : Could not resolve")

    # Try to get the hostname's FQDN
    try:
        fqdn = socket.getfqdn(target)
        info(f"FQDN       : {fqdn}")
    except Exception:
        pass

    success("Basic information gathering completed.")


def port_scan(target):
    """Module 2: Nmap Port Scan"""
    section("NMAP PORT SCAN")
    print(f"  {Color.GREEN}[+] Scanning for open ports...{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    if not check_tool("nmap"):
        error("Nmap is not installed. Install it with: sudo apt install nmap")
        return

    info(f"Running Nmap scan on {ip}...")
    print()
    output = run_cmd(f"nmap -T4 {ip}")
    print(f"{Color.GREEN}{output}{Color.RESET}")

    success("Port scan completed.")


def service_detection(target):
    """Module 3: Service Version Detection"""
    section("SERVICE VERSION DETECTION")
    print(f"  {Color.GREEN}[+] Detecting running services...{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    if not check_tool("nmap"):
        error("Nmap is not installed. Install it with: sudo apt install nmap")
        return

    info(f"Running service detection on {ip}...")
    info("This may take a minute...\n")
    output = run_cmd(f"nmap -sV -T4 {ip}")
    print(f"{Color.GREEN}{output}{Color.RESET}")

    success("Service detection completed.")


def banner_grab(target):
    """Module 4: Banner Grabbing"""
    section("BANNER GRABBING")
    print(f"  {Color.GREEN}[+] Detecting running services via banner grabbing...{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443,
                    445, 993, 995, 3306, 5432, 5900, 6667, 8080, 8443]

    info(f"Grabbing banners from {ip} on {len(common_ports)} common ports...\n")
    found = 0

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            if banner:
                print(f"  {Color.CYAN}[Port {port:>5}]{Color.RESET} {Color.GREEN}{banner[:120]}{Color.RESET}")
                found += 1
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    if found == 0:
        warning("No banners could be grabbed. Ports may be filtered.")

    print()
    success(f"Banner grabbing completed. {found} banner(s) retrieved.")


def dns_lookup(target):
    """Module 5: DNS Lookup"""
    section("DNS LOOKUP")
    print(f"  {Color.GREEN}[+] Performing DNS lookup...{Color.RESET}\n")

    if check_tool("nslookup"):
        output = run_cmd(f"nslookup {target}")
        print(f"{Color.GREEN}{output}{Color.RESET}")
    elif check_tool("dig"):
        output = run_cmd(f"dig {target} ANY +noall +answer")
        print(f"{Color.GREEN}{output}{Color.RESET}")
    else:
        # Fallback: use Python socket
        ip = resolve_target(target)
        if ip:
            info(f"{target} → {ip}")

    success("DNS lookup completed.")


def whois_lookup(target):
    """Module 6: Whois Lookup"""
    section("WHOIS LOOKUP")
    print(f"  {Color.GREEN}[+] Performing WHOIS lookup...{Color.RESET}\n")

    if not check_tool("whois"):
        error("whois is not installed. Install it with: sudo apt install whois")
        return

    output = run_cmd(f"whois {target}")
    # Show first 50 lines to keep it manageable
    lines = output.split("\n")
    for line in lines[:50]:
        print(f"  {Color.GREEN}{line}{Color.RESET}")
    if len(lines) > 50:
        info(f"... ({len(lines) - 50} more lines truncated)")

    success("WHOIS lookup completed.")


def ping_sweep(target):
    """Module 7: Network Ping Sweep"""
    section("NETWORK PING SWEEP")
    print(f"  {Color.GREEN}[+] Scanning for active hosts on the network...{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    # Determine /24 subnet from target IP
    parts = ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    if not check_tool("nmap"):
        error("Nmap is not installed. Install it with: sudo apt install nmap")
        return

    info(f"Scanning subnet {subnet} for active hosts...")
    info("This may take a moment...\n")
    output = run_cmd(f"nmap -sn {subnet}")
    print(f"{Color.GREEN}{output}{Color.RESET}")

    success("Network ping sweep completed.")


def vuln_scan(target):
    """Module 8: Basic Vulnerability Scan"""
    section("VULNERABILITY ASSESSMENT")
    print(f"  {Color.GREEN}[+] Identifying potential vulnerabilities...{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    if not check_tool("nmap"):
        error("Nmap is not installed. Install it with: sudo apt install nmap")
        return

    info(f"Running Nmap vulnerability scripts on {ip}...")
    info("This may take several minutes...\n")
    output = run_cmd(f"nmap -sV --script=vuln -T4 {ip}")
    print(f"{Color.GREEN}{output}{Color.RESET}")

    success("Vulnerability assessment completed.")


def os_detection(target):
    """Module 9: OS Detection"""
    section("OS DETECTION")
    print(f"  {Color.GREEN}[+] Detecting target operating system...{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    if not check_tool("nmap"):
        error("Nmap is not installed. Install it with: sudo apt install nmap")
        return

    warning("OS detection requires root/sudo privileges.")
    info(f"Running OS detection on {ip}...\n")
    output = run_cmd(f"sudo nmap -O -T4 {ip}")
    print(f"{Color.GREEN}{output}{Color.RESET}")

    success("OS detection completed.")


def comprehensive_scan(target):
    """Module A: Run All Scan Modules"""
    section("COMPREHENSIVE SCAN - ALL MODULES")
    print(f"  {Color.GREEN}[+] Starting comprehensive VAPT scan...{Color.RESET}\n")

    basic_info(target)
    port_scan(target)
    service_detection(target)
    banner_grab(target)
    dns_lookup(target)
    whois_lookup(target)
    ping_sweep(target)
    vuln_scan(target)

    print()
    section("COMPREHENSIVE SCAN COMPLETE")
    success("All scan modules have been executed.")


# ─────────────────────── MAIN MENU ────────────────────────────
def print_menu(target):
    print(f"""
  {Color.BOLD}{Color.BLUE}+--------------------------------------------------------------+
  +         Mini VAPT Suite - Scan Selection Menu                +
  +--------------------------------------------------------------+{Color.RESET}

  {Color.CYAN}Target : {Color.GREEN}{target}{Color.RESET}

  {Color.YELLOW} [1]  Basic Information Gathering {Color.RESET}(IP, Hostname, DNS)
  {Color.YELLOW} [2]  Nmap Port Scan             {Color.RESET}(Open Port Detection)
  {Color.YELLOW} [3]  Service Detection           {Color.RESET}(Running Services & Versions)
  {Color.YELLOW} [4]  Banner Grabbing             {Color.RESET}(Service Identification)
  {Color.YELLOW} [5]  DNS Lookup                  {Color.RESET}(DNS Records)
  {Color.YELLOW} [6]  Whois Lookup                {Color.RESET}(Domain Registration Info)
  {Color.YELLOW} [7]  Network Ping Sweep          {Color.RESET}(Active Host Discovery)
  {Color.YELLOW} [8]  Vulnerability Scan          {Color.RESET}(Nmap Vuln Scripts)
  {Color.YELLOW} [9]  OS Detection                {Color.RESET}(Target OS Fingerprinting)
  {Color.BOLD}{Color.CYAN} [A]  Comprehensive Scan          {Color.RESET}(All Modules)
  {Color.BOLD} [B]  Change Target{Color.RESET}
  {Color.BOLD}{Color.RED} [Q]  Quit{Color.RESET}
""")


def main():
    print_banner()

    # ── Target Input ──
    while True:
        target = input(f"  {Color.CYAN}[#]{Color.RESET} Enter the target IP or hostname: {Color.GREEN}").strip()
        print(Color.RESET, end="")

        if not target:
            error("Please enter a valid target.")
            continue

        ip = resolve_target(target)
        if ip:
            info(f"Target resolved: {target} → {ip}")
            break

    # ── Scan Loop ──
    while True:
        print_menu(target)
        choice = input(f"  {Color.CYAN}[#]{Color.RESET} Select a scan option: {Color.GREEN}").strip().upper()
        print(Color.RESET, end="")

        scan_map = {
            "1": basic_info,
            "2": port_scan,
            "3": service_detection,
            "4": banner_grab,
            "5": dns_lookup,
            "6": whois_lookup,
            "7": ping_sweep,
            "8": vuln_scan,
            "9": os_detection,
            "A": comprehensive_scan,
        }

        if choice == "Q":
            print(f"\n  {Color.GREEN}[✓] Mini VAPT Suite - Session Ended. Thank you.{Color.RESET}\n")
            sys.exit(0)
        elif choice == "B":
            # Change target
            while True:
                target = input(f"\n  {Color.CYAN}[#]{Color.RESET} Enter new target IP or hostname: {Color.GREEN}").strip()
                print(Color.RESET, end="")
                if resolve_target(target):
                    info(f"Target changed to: {target}")
                    break
                error("Could not resolve. Try again.")
        elif choice in scan_map:
            scan_map[choice](target)
            input(f"\n  {Color.YELLOW}[✓] Scan Completed. Press Enter to continue...{Color.RESET}")
        else:
            error("Invalid option. Please choose from the menu.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Color.RED}[!] Interrupted by user. Exiting...{Color.RESET}\n")
        sys.exit(0)