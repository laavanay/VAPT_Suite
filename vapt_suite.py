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
import datetime
import ssl
import urllib.request
import urllib.error
import urllib.parse

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

# ─────────────── METASPLOIT MODULE MAP ────────────────────────
METASPLOIT_MODULES = {
    21:   ["exploit/unix/ftp/vsftpd_234_backdoor",
           "auxiliary/scanner/ftp/ftp_login",
           "auxiliary/scanner/ftp/anonymous"],
    22:   ["auxiliary/scanner/ssh/ssh_login",
           "auxiliary/scanner/ssh/ssh_version"],
    23:   ["auxiliary/scanner/telnet/telnet_login",
           "auxiliary/scanner/telnet/telnet_version"],
    25:   ["auxiliary/scanner/smtp/smtp_enum",
           "auxiliary/scanner/smtp/smtp_version"],
    80:   ["auxiliary/scanner/http/http_version",
           "exploit/multi/http/php_cgi_arg_injection",
           "exploit/unix/webapp/php_include_w_shell"],
    139:  ["exploit/multi/samba/usermap_script",
           "auxiliary/scanner/smb/smb_version",
           "auxiliary/scanner/smb/smb_login"],
    445:  ["exploit/windows/smb/ms17_010_eternalblue",
           "auxiliary/scanner/smb/smb_ms17_010"],
    3306: ["auxiliary/scanner/mysql/mysql_login",
           "auxiliary/scanner/mysql/mysql_version",
           "exploit/multi/mysql/mysql_udf_payload"],
    5432: ["auxiliary/scanner/postgres/postgres_login",
           "exploit/multi/postgres/postgres_copy_from_program"],
    5900: ["auxiliary/scanner/vnc/vnc_login",
           "auxiliary/scanner/vnc/vnc_none_auth"],
    6667: ["exploit/unix/irc/unreal_ircd_3281_backdoor"],
    8080: ["auxiliary/scanner/http/tomcat_mgr_login",
           "exploit/multi/http/tomcat_mgr_upload"],
}

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


def web_vuln_check(target):
    """Module W: Web Application Vulnerability Check (Burp Suite context)"""
    section("WEB APPLICATION VULNERABILITY CHECK")
    print(f"  {Color.GREEN}[+] Testing web services for common vulnerabilities...{Color.RESET}\n")
    ip = resolve_target(target)
    if not ip:
        return

    web_ports = []
    for p in [80, 8080, 443, 8443]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((ip, p)) == 0:
                web_ports.append(p)
            s.close()
        except Exception:
            pass

    if not web_ports:
        warning("No web services detected on ports 80, 8080, 443, 8443.")
        return

    info(f"Web ports open: {', '.join(str(p) for p in web_ports)}\n")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port in web_ports:
        scheme = "https" if port in [443, 8443] else "http"
        base   = f"{scheme}://{ip}:{port}"
        print(f"  {Color.BOLD}{Color.BLUE}┌─ Port {port} — {scheme.upper()} ──────────────────────────────┐{Color.RESET}\n")

        # ── Security Headers ──────────────────────────────────
        info("Security Header Analysis:")
        try:
            req  = urllib.request.Request(base + "/", headers={"User-Agent": "MiniVAPT/2.0"})
            kw   = {"context": ctx} if scheme == "https" else {}
            resp = urllib.request.urlopen(req, timeout=5, **kw)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            for hdr, desc in [
                ("x-frame-options",          "Clickjacking Protection"),
                ("x-content-type-options",   "MIME Sniffing Protection"),
                ("content-security-policy",  "Content Security Policy"),
                ("strict-transport-security","HSTS — Force HTTPS"),
                ("x-xss-protection",         "XSS Filter Header"),
            ]:
                if hdrs.get(hdr):
                    success(f"  {hdr}: {hdrs[hdr][:60]}")
                else:
                    warning(f"  MISSING: {hdr} — {desc}")
            srv = hdrs.get("server")
            if srv:
                warning(f"  Server version disclosed: {srv}")
            else:
                success("  Server header: Hidden ✓")
        except Exception as e:
            warning(f"  Could not fetch headers: {e}")
        print()

        # ── Sensitive Path Probe ──────────────────────────────
        info("Probing for sensitive / exposed paths:")
        found = False
        for path in ["/admin", "/phpmyadmin", "/dvwa", "/manager/html",
                     "/robots.txt", "/wp-admin", "/server-status",
                     "/backup", "/login", "/config.php", "/test"]:
            try:
                req  = urllib.request.Request(base + path,
                                              headers={"User-Agent": "MiniVAPT/2.0"})
                kw   = {"context": ctx} if scheme == "https" else {}
                resp = urllib.request.urlopen(req, timeout=3, **kw)
                print(f"    {Color.RED}[EXPOSED]{Color.RESET} {path} → HTTP {resp.status}")
                found = True
            except urllib.error.HTTPError as e:
                if e.code in [301, 302, 403]:
                    print(f"    {Color.YELLOW}[{e.code}]{Color.RESET} {path}")
            except Exception:
                pass
        if not found:
            success("  No common sensitive paths exposed.")
        print()

    success("Web check complete. Use Burp Suite to intercept and test requests manually.")


def packet_capture(target):
    """Module P: Network Traffic Capture (Wireshark/tcpdump context)"""
    section("NETWORK PACKET CAPTURE")
    print(f"  {Color.GREEN}[+] Capturing live traffic to/from target...{Color.RESET}\n")
    ip = resolve_target(target)
    if not ip:
        return

    if check_tool("tshark"):
        tool = "tshark"
    elif check_tool("tcpdump"):
        tool = "tcpdump"
    else:
        error("Neither tshark nor tcpdump found.")
        info("Install: sudo apt install tshark")
        info(f"Or open Wireshark on Kali Linux and filter: ip.addr == {ip}")
        return

    duration = 10
    warning("Root/sudo privileges are required for packet capture.")
    info(f"Capturing {duration}s of traffic to/from {ip} using {tool}...\n")

    if tool == "tshark":
        cmd = (f"sudo tshark -i any -f 'host {ip}' "
               f"-a duration:{duration} -q -z io,phs 2>/dev/null")
    else:
        cmd = f"sudo tcpdump -i any -n -c 100 host {ip} 2>/dev/null"

    output = run_cmd(cmd)
    if output:
        print(f"{Color.GREEN}{output}{Color.RESET}")
    else:
        warning("No traffic captured. Run a scan module first to generate traffic.")
    print()
    success("Capture complete.")
    info(f"For GUI analysis: open Wireshark on Kali → filter: ip.addr == {ip}")


def metasploit_suggest(target):
    """Module E: Metasploit Exploit / Auxiliary Suggestions"""
    section("METASPLOIT EXPLOIT SUGGESTIONS")
    print(f"  {Color.GREEN}[+] Mapping open services to Metasploit modules...{Color.RESET}\n")
    ip = resolve_target(target)
    if not ip:
        return

    info(f"Scanning {ip} for ports with known Metasploit modules...")
    open_ports = []
    for port in list(METASPLOIT_MODULES.keys()):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass

    if not open_ports:
        success("No relevant open ports found. Target appears hardened.")
        return

    info(f"Found {len(open_ports)} port(s) with known MSF modules: "
         f"{', '.join(str(p) for p in open_ports)}\n")
    warning("Use ONLY on Metasploitable 2 in a controlled lab. "
            "Never run exploits on unauthorized systems.\n")

    if not check_tool("msfconsole"):
        warning("Metasploit not found. Install: sudo apt install metasploit-framework\n")
    else:
        success("Metasploit Framework detected.\n")

    for port in open_ports:
        svc  = MITIGATION_DB.get(port, {}).get("service", f"Port {port}")
        mods = METASPLOIT_MODULES[port]
        print(f"  {Color.BOLD}{Color.CYAN}Port {port} — {svc}{Color.RESET}")
        for mod in mods:
            col = Color.RED    if mod.startswith("exploit") else Color.YELLOW
            tag = "[EXPLOIT  ]" if mod.startswith("exploit") else "[AUXILIARY]"
            print(f"    {col}{tag}{Color.RESET} use {mod}")
        exploits = [m for m in mods if m.startswith("exploit")]
        if exploits:
            print(f"  {Color.GREEN}  Quick-start in msfconsole:")
            print(f"      msf6 > use {exploits[0]}")
            print(f"      msf6 > set RHOSTS {ip}")
            print(f"      msf6 > run{Color.RESET}")
        print()
    success("Module suggestions generated. Launch Metasploit: sudo msfconsole")


def generate_report(target):
    """Module R: Save Security Assessment Report to a file"""
    section("SECURITY ASSESSMENT REPORT GENERATOR")
    print(f"  {Color.GREEN}[+] Running assessment and saving report...{Color.RESET}\n")
    ip = resolve_target(target)
    if not ip:
        return

    ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"vapt_report_{ip.replace('.', '_')}_{ts}.txt"
    sep   = "=" * 68
    L     = []

    def ln(t=""):
        L.append(t)

    ln(sep)
    ln("   MINI VAPT SUITE v2.0  —  SECURITY ASSESSMENT REPORT")
    ln(sep)
    ln(f"  Date        : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    ln(f"  Target      : {target}  ({ip})")
    ln(f"  Environment : Kali Linux → Metasploitable 2 (VMware Workstation)")
    ln(f"  Tools Used  : Nmap, Python, Wireshark, Burp Suite, Metasploit, OpenVAS, Nessus")
    ln(f"  Disclaimer  : Educational / lab use only")
    ln(sep); ln()

    # Section 1 — Basic info
    ln("[ SECTION 1: BASIC INFORMATION ]"); ln("-" * 40)
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = "N/A"
    ln(f"  Hostname : {hostname}")
    ln(f"  FQDN     : {socket.getfqdn(target)}"); ln()

    # Section 2 — Port scan
    ln("[ SECTION 2: OPEN PORT DISCOVERY ]"); ln("-" * 40)
    info("Scanning ports for report...")
    all_ports = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443,
                 445, 993, 995, 3306, 5432, 5900, 6667, 8080, 8443]
    open_ports = []
    for port in all_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    if open_ports:
        for port in open_ports:
            svc  = MITIGATION_DB.get(port, {}).get("service", "Unknown")
            risk = MITIGATION_DB.get(port, {}).get("risk",    "UNKNOWN")
            ln(f"  PORT {port:<6} | {svc:<22} | Risk: {risk}")
        success(f"Found {len(open_ports)} open port(s).")
    else:
        ln("  No open ports found on common ports.")
    ln()

    # Section 3 — Risk summary
    ln("[ SECTION 3: RISK SUMMARY ]"); ln("-" * 40)
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        pts = [p for p in open_ports if MITIGATION_DB.get(p, {}).get("risk") == level]
        ln(f"  {level:<10}: {len(pts)} port(s)  →  "
           f"{', '.join(str(p) for p in pts) or 'None'}")
    ln()

    # Section 4 — Detailed findings
    ln("[ SECTION 4: DETAILED FINDINGS & MITIGATIONS ]"); ln("-" * 40)
    for port in open_ports:
        entry = MITIGATION_DB.get(port)
        if entry:
            ln(f"\n  Port {port} — {entry['service']} (Risk: {entry['risk']})")
            ln("  Issues:")
            for iss in entry["issues"]:
                ln(f"    • {iss}")
            ln("  Mitigations:")
            for i, fix in enumerate(entry["mitigations"], 1):
                ln(f"    {i}. {fix}")
    ln()

    # Section 5 — Metasploit suggestions
    ln("[ SECTION 5: METASPLOIT MODULE SUGGESTIONS ]"); ln("-" * 40)
    for port in open_ports:
        mods = METASPLOIT_MODULES.get(port, [])
        if mods:
            svc = MITIGATION_DB.get(port, {}).get("service", f"Port {port}")
            ln(f"\n  Port {port} — {svc}:")
            for mod in mods:
                ln(f"    use {mod}")
    ln()

    # Section 6 — General hardening
    ln("[ SECTION 6: GENERAL HARDENING RECOMMENDATIONS ]"); ln("-" * 40)
    for i, rec in enumerate([
        "sudo apt update && sudo apt upgrade      (keep all packages updated)",
        "sudo ufw enable; sudo ufw default deny incoming  (enable firewall)",
        "sudo systemctl disable <service>         (disable unused services)",
        "Deploy IDS/IPS: Snort or Suricata for real-time monitoring",
        "Enable centralized logging (rsyslog) and review regularly",
        "Apply principle of least privilege for all user accounts",
        "Run regular VAPT scans and patch findings promptly",
    ], 1):
        ln(f"  {i}. {rec}")
    ln(); ln(sep); ln("  END OF REPORT — Mini VAPT Suite v2.0"); ln(sep)

    with open(fname, "w") as f:
        f.write("\n".join(L))
    print()
    success(f"Report saved: {Color.CYAN}{fname}{Color.RESET}")
    info(f"View it with: cat {fname}")


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
    os_detection(target)
    web_vuln_check(target)
    packet_capture(target)
    metasploit_suggest(target)
    mitigation_report(target)
    generate_report(target)

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

  {Color.YELLOW} [1]  Basic Information Gathering {Color.RESET}(IP, Hostname, FQDN)
  {Color.YELLOW} [2]  Nmap Port Scan             {Color.RESET}(Open Port Detection)
  {Color.YELLOW} [3]  Service Detection           {Color.RESET}(Running Services & Versions)
  {Color.YELLOW} [4]  Banner Grabbing             {Color.RESET}(Service Identification)
  {Color.YELLOW} [5]  DNS Lookup                  {Color.RESET}(DNS Records)
  {Color.YELLOW} [6]  Whois Lookup                {Color.RESET}(Domain Registration Info)
  {Color.YELLOW} [7]  Network Ping Sweep          {Color.RESET}(Active Host Discovery)
  {Color.YELLOW} [8]  Vulnerability Scan          {Color.RESET}(Nmap Vuln Scripts)
  {Color.YELLOW} [9]  OS Detection                {Color.RESET}(Target OS Fingerprinting)
  {Color.YELLOW} [W]  Web Vuln Check              {Color.RESET}(Burp Suite context — Headers, Paths)
  {Color.YELLOW} [P]  Packet Capture              {Color.RESET}(Wireshark/tcpdump — Live Traffic)
  {Color.YELLOW} [E]  Metasploit Suggestions      {Color.RESET}(Exploit Module Mapping)
  {Color.YELLOW} [M]  Mitigation Report           {Color.RESET}(Remediation Strategy)
  {Color.YELLOW} [R]  Save Report to File         {Color.RESET}(Full Assessment Report)
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
            "W": web_vuln_check,
            "P": packet_capture,
            "E": metasploit_suggest,
            "M": mitigation_report,
            "R": generate_report,
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