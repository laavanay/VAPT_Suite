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


# ─────────────── MITIGATION KNOWLEDGE BASE ────────────────────

MITIGATION_DB = {
    21: {
        "service": "FTP",
        "risk": "HIGH",
        "issues": [
            "Plaintext credentials (no encryption)",
            "Anonymous login may be enabled",
            "Known exploits for older FTP daemons (e.g., vsftpd 2.3.4 backdoor)"
        ],
        "mitigations": [
            "Disable FTP if not required — use SFTP (SSH File Transfer) instead",
            "If FTP is required, enforce TLS (FTPS) via 'ssl_enable=YES' in vsftpd.conf",
            "Disable anonymous login: 'anonymous_enable=NO'",
            "Restrict FTP users with chroot: 'chroot_local_user=YES'",
            "Update FTP daemon to the latest version",
            "Implement IP-based access control via /etc/hosts.allow and /etc/hosts.deny",
            "Firewall rule: iptables -A INPUT -p tcp --dport 21 -s <trusted_ip> -j ACCEPT"
        ]
    },
    22: {
        "service": "SSH",
        "risk": "MEDIUM",
        "issues": [
            "Brute force attacks on weak passwords",
            "Older SSH versions may have vulnerabilities",
            "Root login may be permitted"
        ],
        "mitigations": [
            "Disable root login: set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            "Use key-based authentication instead of passwords",
            "Disable password auth: 'PasswordAuthentication no'",
            "Change default port: 'Port 2222' (security through obscurity)",
            "Install fail2ban to block brute force: 'sudo apt install fail2ban'",
            "Limit SSH access to specific users: 'AllowUsers <username>'",
            "Update OpenSSH to the latest version"
        ]
    },
    23: {
        "service": "Telnet",
        "risk": "CRITICAL",
        "issues": [
            "All data transmitted in plaintext (including passwords)",
            "No encryption whatsoever",
            "Easily sniffable on the network"
        ],
        "mitigations": [
            "DISABLE Telnet immediately — it should never be used",
            "Replace with SSH for all remote access needs",
            "Remove telnet daemon: 'sudo apt remove telnetd'",
            "Block port 23: 'iptables -A INPUT -p tcp --dport 23 -j DROP'",
            "If legacy systems require it, tunnel Telnet through SSH"
        ]
    },
    25: {
        "service": "SMTP",
        "risk": "HIGH",
        "issues": [
            "Open relay may allow spam sending",
            "User enumeration via VRFY/EXPN commands",
            "Plaintext email transmission"
        ],
        "mitigations": [
            "Disable open relay in SMTP configuration",
            "Disable VRFY and EXPN commands",
            "Enforce TLS/STARTTLS for encrypted email transmission",
            "Implement SPF, DKIM, and DMARC records",
            "Restrict SMTP access to authorized users only",
            "Update mail server software to latest version"
        ]
    },
    53: {
        "service": "DNS",
        "risk": "MEDIUM",
        "issues": [
            "DNS zone transfer may leak internal network info",
            "DNS amplification attacks possible",
            "Cache poisoning vulnerabilities"
        ],
        "mitigations": [
            "Restrict zone transfers: 'allow-transfer { trusted_servers; };'",
            "Enable DNSSEC to prevent cache poisoning",
            "Use response rate limiting (RRL) to prevent amplification",
            "Run DNS server on internal network only if not public-facing",
            "Update DNS software (BIND/dnsmasq) to latest version"
        ]
    },
    80: {
        "service": "HTTP",
        "risk": "HIGH",
        "issues": [
            "Unencrypted web traffic",
            "Web application vulnerabilities (XSS, SQLi, etc.)",
            "Server version disclosure in headers"
        ],
        "mitigations": [
            "Redirect all HTTP to HTTPS (port 443)",
            "Hide server version: 'ServerTokens Prod' (Apache) or 'server_tokens off' (Nginx)",
            "Enable security headers: X-Frame-Options, CSP, X-Content-Type-Options",
            "Keep web server and applications updated",
            "Use a Web Application Firewall (WAF)",
            "Disable directory listing: 'Options -Indexes'"
        ]
    },
    110: {
        "service": "POP3",
        "risk": "HIGH",
        "issues": [
            "Plaintext credential transmission",
            "Email content transmitted without encryption"
        ],
        "mitigations": [
            "Disable POP3 and use POP3S (port 995) with SSL/TLS",
            "If POP3 is required, enforce STARTTLS",
            "Update mail server software",
            "Restrict access via firewall to known mail clients"
        ]
    },
    111: {
        "service": "RPCbind",
        "risk": "HIGH",
        "issues": [
            "Exposes RPC services to the network",
            "Can be used for service enumeration",
            "Known vulnerabilities in older versions"
        ],
        "mitigations": [
            "Disable RPCbind if NFS/NIS is not needed: 'sudo systemctl disable rpcbind'",
            "Restrict access via firewall to trusted hosts only",
            "Block port 111: 'iptables -A INPUT -p tcp --dport 111 -s ! <trusted> -j DROP'",
            "Keep rpcbind updated to latest version"
        ]
    },
    139: {
        "service": "NetBIOS/SMB",
        "risk": "CRITICAL",
        "issues": [
            "SMBv1 is vulnerable to EternalBlue (WannaCry, NotPetya)",
            "File shares may be publicly accessible",
            "Credential leakage possible"
        ],
        "mitigations": [
            "Disable SMBv1 completely: 'echo 1 > /proc/sys/net/ipv4/conf/all/disable_ipv6'",
            "Use SMBv3 with encryption enabled",
            "Set strong passwords for all SMB users",
            "Restrict share permissions — no anonymous access",
            "Block ports 139/445 from external networks",
            "Update Samba to latest version"
        ]
    },
    143: {
        "service": "IMAP",
        "risk": "HIGH",
        "issues": [
            "Plaintext credential transmission",
            "Email content visible on network"
        ],
        "mitigations": [
            "Disable IMAP, use IMAPS (port 993) with SSL/TLS",
            "Enforce STARTTLS if IMAP is needed",
            "Update mail server to latest version",
            "Restrict access to authorized networks"
        ]
    },
    443: {
        "service": "HTTPS",
        "risk": "LOW",
        "issues": [
            "Outdated TLS versions (TLS 1.0/1.1)",
            "Weak cipher suites",
            "Expired or self-signed certificates"
        ],
        "mitigations": [
            "Enforce TLS 1.2+ only — disable SSLv3, TLS 1.0, TLS 1.1",
            "Use strong cipher suites (ECDHE, AES-GCM)",
            "Use valid certificates from a trusted CA (Let's Encrypt)",
            "Enable HSTS header to prevent downgrade attacks",
            "Regularly scan with SSL Labs (ssllabs.com)"
        ]
    },
    445: {
        "service": "SMB",
        "risk": "CRITICAL",
        "issues": [
            "Direct SMB — primary target for EternalBlue exploits",
            "Ransomware propagation vector",
            "Unauthorized file access"
        ],
        "mitigations": [
            "Disable SMBv1: 'sudo smbcontrol all close-denied-sids'",
            "Apply all security patches (MS17-010 for EternalBlue)",
            "Block port 445 at the perimeter firewall",
            "Enable SMB signing to prevent MITM attacks",
            "Use strong authentication — disable guest access",
            "Regularly audit shared folders and permissions"
        ]
    },
    3306: {
        "service": "MySQL",
        "risk": "HIGH",
        "issues": [
            "Database exposed to network — should be internal only",
            "Default credentials may be in use",
            "SQL injection if web apps connect to it"
        ],
        "mitigations": [
            "Bind MySQL to localhost only: 'bind-address = 127.0.0.1' in my.cnf",
            "Remove default/test databases: 'DROP DATABASE test;'",
            "Set strong root password and remove anonymous users",
            "Run 'mysql_secure_installation' to harden defaults",
            "Block port 3306 at the firewall for external access",
            "Use SSL for database connections"
        ]
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "HIGH",
        "issues": [
            "Database exposed to network",
            "Default trust authentication may allow unauthenticated access"
        ],
        "mitigations": [
            "Bind to localhost: 'listen_addresses = localhost' in postgresql.conf",
            "Use md5/scram-sha-256 auth in pg_hba.conf instead of 'trust'",
            "Set strong passwords for all database users",
            "Block port 5432 at the firewall",
            "Enable SSL connections in postgresql.conf"
        ]
    },
    5900: {
        "service": "VNC",
        "risk": "CRITICAL",
        "issues": [
            "VNC often has weak or no authentication",
            "Traffic is unencrypted by default",
            "Full remote desktop access if compromised"
        ],
        "mitigations": [
            "Disable VNC if not needed",
            "Use SSH tunneling for VNC: 'ssh -L 5900:localhost:5900 user@host'",
            "Set a strong VNC password",
            "Restrict VNC to localhost and tunnel through SSH",
            "Block port 5900 at the firewall"
        ]
    },
    6667: {
        "service": "IRC",
        "risk": "HIGH",
        "issues": [
            "UnrealIRCd 3.2.8.1 has a known backdoor",
            "Often used for botnet C2 communication",
            "Plaintext protocol"
        ],
        "mitigations": [
            "Disable IRC if not required",
            "Update IRC daemon to latest version",
            "Block port 6667 at the firewall",
            "Monitor for unusual IRC traffic patterns"
        ]
    },
    8080: {
        "service": "HTTP-Proxy/Alt-HTTP",
        "risk": "HIGH",
        "issues": [
            "Alternative HTTP port — may host admin panels",
            "Often used by development/test servers left open",
            "May expose sensitive management interfaces"
        ],
        "mitigations": [
            "Disable if not needed — close unnecessary web servers",
            "Apply same hardening as port 80 (hide version, security headers)",
            "Restrict access to admin interfaces via IP whitelist",
            "Use HTTPS instead of HTTP on this port"
        ]
    },
    8443: {
        "service": "HTTPS-Alt",
        "risk": "MEDIUM",
        "issues": [
            "Alternative HTTPS port — may host management consoles",
            "Same TLS risks as port 443"
        ],
        "mitigations": [
            "Apply same hardening as port 443",
            "Restrict access to authorized IPs only",
            "Ensure valid TLS certificates are in use"
        ]
    },
}

# General mitigations for unknown ports
GENERAL_MITIGATIONS = [
    "Close the port if the service is not required",
    "Update the service software to the latest version",
    "Restrict access using firewall rules (iptables/ufw)",
    "Monitor logs for suspicious activity on this port",
    "Use intrusion detection systems (IDS) like Snort or Suricata"
]

RISK_COLORS = {
    "CRITICAL": Color.RED,
    "HIGH": Color.YELLOW,
    "MEDIUM": Color.CYAN,
    "LOW": Color.GREEN,
}


def mitigation_report(target):
    """Module 10: Mitigation Strategy Report"""
    section("MITIGATION STRATEGY REPORT")
    print(f"  {Color.GREEN}[+] Scanning target and generating mitigation plan...{Color.RESET}\n")

    ip = resolve_target(target)
    if not ip:
        return

    # Step 1: Discover open ports via socket scan
    info(f"Scanning {ip} for open ports...")
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443,
                  445, 993, 995, 3306, 5432, 5900, 6667, 8080, 8443]

    open_ports = []
    for port in scan_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    if not open_ports:
        success("No open ports found on common ports. Target appears well-hardened.")
        return

    info(f"Found {len(open_ports)} open port(s): {', '.join(str(p) for p in open_ports)}\n")

    # Step 2: Generate mitigation report for each open port
    critical_count = 0
    high_count = 0

    for port in open_ports:
        entry = MITIGATION_DB.get(port)

        if entry:
            risk_color = RISK_COLORS.get(entry["risk"], Color.YELLOW)
            print(f"  {Color.BOLD}{Color.BLUE}┌──────────────────────────────────────────────────────┐{Color.RESET}")
            print(f"  {Color.BOLD}{Color.BLUE}│{Color.RESET}  Port {Color.CYAN}{port}{Color.RESET} — {Color.BOLD}{entry['service']}{Color.RESET}  |  Risk: {risk_color}{Color.BOLD}{entry['risk']}{Color.RESET}")
            print(f"  {Color.BOLD}{Color.BLUE}└──────────────────────────────────────────────────────┘{Color.RESET}")

            if entry["risk"] == "CRITICAL":
                critical_count += 1
            elif entry["risk"] == "HIGH":
                high_count += 1

            print(f"  {Color.RED}  Issues:{Color.RESET}")
            for issue in entry["issues"]:
                print(f"    {Color.RED}•{Color.RESET} {issue}")

            print(f"  {Color.GREEN}  Recommended Mitigations:{Color.RESET}")
            for i, fix in enumerate(entry["mitigations"], 1):
                print(f"    {Color.GREEN}{i}.{Color.RESET} {fix}")
            print()
        else:
            print(f"  {Color.BOLD}{Color.BLUE}┌──────────────────────────────────────────────────────┐{Color.RESET}")
            print(f"  {Color.BOLD}{Color.BLUE}│{Color.RESET}  Port {Color.CYAN}{port}{Color.RESET} — {Color.BOLD}Unknown Service{Color.RESET}  |  Risk: {Color.YELLOW}{Color.BOLD}UNKNOWN{Color.RESET}")
            print(f"  {Color.BOLD}{Color.BLUE}└──────────────────────────────────────────────────────┘{Color.RESET}")
            print(f"  {Color.GREEN}  General Mitigations:{Color.RESET}")
            for i, fix in enumerate(GENERAL_MITIGATIONS, 1):
                print(f"    {Color.GREEN}{i}.{Color.RESET} {fix}")
            print()

    # Step 3: Summary
    section("MITIGATION SUMMARY")
    total = len(open_ports)
    info(f"Total open ports analyzed : {total}")
    if critical_count:
        print(f"  {Color.RED}[!] CRITICAL risk ports   : {critical_count}{Color.RESET}")
    if high_count:
        print(f"  {Color.YELLOW}[!] HIGH risk ports       : {high_count}{Color.RESET}")
    med_low = total - critical_count - high_count
    if med_low:
        print(f"  {Color.CYAN}[i] MEDIUM/LOW risk ports : {med_low}{Color.RESET}")

    print(f"\n  {Color.BOLD}General Hardening Recommendations:{Color.RESET}")
    general_recs = [
        "Keep all system packages updated: 'sudo apt update && sudo apt upgrade'",
        "Enable a host-based firewall (ufw/iptables) and deny all by default",
        "Disable all unnecessary services: 'sudo systemctl disable <service>'",
        "Implement network segmentation between critical systems",
        "Deploy an IDS/IPS (Snort, Suricata) for network monitoring",
        "Enable centralized logging (syslog/rsyslog) and monitor regularly",
        "Conduct regular vulnerability scans and patch promptly",
        "Follow the principle of least privilege for all accounts",
    ]
    for i, rec in enumerate(general_recs, 1):
        print(f"    {Color.GREEN}{i}.{Color.RESET} {rec}")

    print()
    success("Mitigation strategy report generated successfully.")


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
    mitigation_report(target)

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
  {Color.YELLOW} [M]  Mitigation Report           {Color.RESET}(Remediation Strategy)
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
            "M": mitigation_report,
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