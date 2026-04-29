# Mini VAPT Suite
### Mini Vulnerability Assessment and Penetration Testing Suite

Mini VAPT Suite is a Python-based security tool that performs network reconnaissance, port scanning, service identification, vulnerability detection, and mitigation reporting — all from a single interactive terminal interface. Designed for use in a controlled lab environment (Kali Linux → Metasploitable 2).

---

## 1. Problem Statement

Computer systems and networks are constantly exposed to various security threats and vulnerabilities.

Common security issues include:
- Open ports and insecure services
- Weak system configurations
- Outdated software
- Unauthorized network access

Many users and organizations fail to identify these vulnerabilities before attackers exploit them.

Therefore, there is a need for a simple tool that can scan systems and identify security weaknesses.

---

## 2. Project Objectives

The main objectives of the Mini VAPT Suite project are:

- Perform basic network reconnaissance
- Scan target systems for open ports
- Identify running services on the system
- Detect potential security vulnerabilities
- Provide basic security assessment results
- Help users understand possible risks in their system
- Generate actionable mitigation strategies for discovered vulnerabilities
- Recommend specific remediation steps for each identified risk

---

## 3. Type of VAPT Performed

This project falls under:

**VAPT of a Local Network / Host System**

The tool scans a target system or network to identify:
- Open ports
- Active hosts
- Running services
- Possible security vulnerabilities

This helps evaluate the security posture of the target environment.

---

## 4. Lab Environment Setup

| Component               | Details                                |
|-------------------------|----------------------------------------|
| Operating System        | Kali Linux                             |
| Target Environment      | Metasploitable 2 / Test Linux Machine  |
| Virtualization Platform | VMware Workstation                     |

**Network Configuration:**
- Attacker Machine – Kali Linux
- Target Machine – Metasploitable 2
- Both systems connected in same virtual network

---

## 5. Tools Used

- Burp Suite
- Nmap
- Nessus
- Wireshark
- Python
- OpenVAS
- Metasploit

---

## 6. Scan Modules

| #  | Module                      | Description                                            |
|----|-----------------------------|--------------------------------------------------------|
| 1  | Basic Information Gathering | IP address, hostname, reverse DNS, FQDN                |
| 2  | Nmap Port Scan              | Detects open ports on the target                       |
| 3  | Service Detection           | Identifies running services and their versions         |
| 4  | Banner Grabbing             | Connects to ports and reads service banners            |
| 5  | DNS Lookup                  | Resolves DNS records for the target                    |
| 6  | Whois Lookup                | Domain/IP registration details                         |
| 7  | Network Ping Sweep          | Discovers active hosts on the target subnet            |
| 8  | Vulnerability Scan          | Runs Nmap vulnerability detection scripts              |
| 9  | OS Detection                | Fingerprints the target operating system               |
| M  | **Mitigation Report**       | **Generates risk-rated remediation strategies per port** |
| A  | Comprehensive Scan          | Runs all modules sequentially                          |

---

## 6.1 Mitigation Strategy

The **Mitigation Report** module (option `M`) is a key differentiator of this tool. After scanning the target for open ports, it:

1. **Identifies each open port** and maps it to a known service
2. **Assigns a risk level** (CRITICAL / HIGH / MEDIUM / LOW) to each service
3. **Lists specific security issues** associated with the service
4. **Provides actionable remediation steps** including:
   - Configuration changes (e.g., disable root SSH login, bind MySQL to localhost)
   - Firewall rules (iptables/ufw commands)
   - Service replacement recommendations (e.g., replace Telnet with SSH)
   - Software update guidance
5. **Generates a summary** with general hardening recommendations

### Services Covered

| Risk Level | Services |
|------------|----------|
| CRITICAL   | Telnet (23), NetBIOS/SMB (139), SMB (445), VNC (5900) |
| HIGH       | FTP (21), SMTP (25), HTTP (80), POP3 (110), RPCbind (111), IMAP (143), MySQL (3306), PostgreSQL (5432), IRC (6667), HTTP-Alt (8080) |
| MEDIUM     | SSH (22), DNS (53), HTTPS-Alt (8443) |
| LOW        | HTTPS (443) |

---

## 7. Installation & Usage

### Prerequisites (on Kali Linux)
```bash
# Nmap (pre-installed on Kali)
sudo apt install nmap

# Whois (pre-installed on Kali)
sudo apt install whois

# Python 3 (pre-installed on Kali)
python3 --version
```

### Running the Tool
```bash
# Clone the repository
git clone <repository_url>
cd "VAPT Suite"

# Run the scanner
python3 vapt_suite.py

# Or make it executable and run directly
chmod +x vapt_suite.py
./vapt_suite.py
```

### Usage Steps
1. Launch the tool with `python3 vapt_suite.py`
2. Enter the target IP address or hostname (e.g., the Metasploitable IP)
3. Select a scan module from the menu (1–9, M for mitigation, A for all)
4. Review the color-coded results displayed in the terminal
5. Run the **Mitigation Report** (`M`) to get remediation strategies
6. Press Enter to return to the menu after each scan
7. Press `B` to change target, or `Q` to quit

---

## 8. Disclaimer

> **This tool is developed strictly for educational purposes and should only be used in a controlled lab environment (Kali Linux → Metasploitable 2 on VMware).**
>
> Unauthorized scanning of systems without explicit permission is illegal. The developers assume no responsibility for misuse.
