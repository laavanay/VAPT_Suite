# Mini VAPT Suite
## Vulnerability Assessment and Penetration Testing Tool

---

## 1. Problem Statement

Computer systems and networks are constantly exposed to various security threats and vulnerabilities.

Common security issues include:

- **Open ports and insecure services** — Unused or misconfigured ports expose systems to exploitation.
- **Weak system configurations** — Default settings, weak passwords, and unpatched software create attack vectors.
- **Outdated software** — Legacy applications carry known Common Vulnerabilities and Exposures (CVEs).
- **Unauthorized network access** — Lack of access control allows adversaries to move laterally across networks.

Many users and organizations fail to identify these vulnerabilities before attackers exploit them. Manual inspection is tedious, and enterprise tools like Nessus or OpenVAS require significant setup and licensing.

**Therefore, there is a need for a simple, automated tool that can scan systems and identify security weaknesses in a controlled lab environment — which is the purpose of the Mini VAPT Suite.**

---

## 2. Project Objectives

The main objectives of the **Mini VAPT Suite** project are:

| # | Objective |
|---|-----------|
| 1 | Perform basic network reconnaissance |
| 2 | Scan target systems for open ports |
| 3 | Identify running services on the system |
| 4 | Detect potential security vulnerabilities |
| 5 | Provide basic security assessment results |
| 6 | Help users understand possible risks in their system |
| 7 | Generate actionable mitigation strategies for discovered vulnerabilities |
| 8 | Recommend specific remediation steps for each identified risk |

---

## 3. Type of VAPT Performed

This project falls under:

> **VAPT of a Local Network / Host System**

The tool scans a target system or network to identify:

- Open ports
- Active hosts
- Running services
- Possible security vulnerabilities

This helps evaluate the **security posture** of the target environment without requiring any special agent installation on the target machine. The assessment is performed externally from the attacker machine (Kali Linux) towards the target (Metasploitable 2), simulating a real-world black-box VAPT scenario.

---

## 4. Lab Environment Setup

### 4.1 Operating System

| Role              | Operating System       |
|-------------------|------------------------|
| Attacker Machine  | Kali Linux             |
| Target Machine    | Metasploitable 2       |

### 4.2 Target Environment

**Metasploitable 2** is a deliberately vulnerable Linux virtual machine designed for practicing penetration testing. It includes:
- Multiple intentionally open and vulnerable services (FTP, Telnet, SMB, MySQL, etc.)
- Weak credentials and default configurations
- A safe, legal environment to run security scans

### 4.3 Virtualization Platform

**VMware Workstation** is used to host both virtual machines.

### 4.4 Network Configuration

```
┌─────────────────────────────────┐
│       VMware Virtual Network    │
│                                 │
│  ┌──────────────┐               │
│  │  Kali Linux  │◄─────── Attacker Machine (runs Mini VAPT Suite)
│  │ (Attacker)   │               │
│  └──────┬───────┘               │
│         │  Host-Only / NAT      │
│         │  Virtual Network      │
│  ┌──────▼───────┐               │
│  │Metasploitable│◄─────── Target Machine (deliberately vulnerable)
│  │      2       │               │
│  └──────────────┘               │
└─────────────────────────────────┘
```

- **Attacker Machine** — Kali Linux (runs the Mini VAPT Suite Python tool)
- **Target Machine** — Metasploitable 2
- Both systems are connected in the **same virtual network** (VMware Host-Only or NAT)
- The tool is executed on Kali Linux, targeting the Metasploitable IP address

---

## 5. Tools Used

| Tool          | Purpose in Project |
|---------------|--------------------|
| **Nmap**      | Port scanning, service detection, OS fingerprinting, vulnerability scripting (`--script=vuln`) |
| **Python 3**  | Core scripting language used to build the Mini VAPT Suite tool |
| **Wireshark** | Packet analysis and network traffic monitoring during scans |
| **Metasploit**| Post-exploitation framework — used in conjunction with scan findings |
| **Burp Suite**| Web application vulnerability testing (HTTP/HTTPS service testing) |
| **Nessus**    | Commercial vulnerability scanner — used for comparative assessment |
| **OpenVAS**   | Open-source vulnerability assessment scanner — used for validation |

---

## 6. Scan Modules

The Mini VAPT Suite implements the following modular scan capabilities:

| Option | Module                    | Description                                                              |
|--------|---------------------------|--------------------------------------------------------------------------|
| `1`    | Basic Information Gathering | Resolves IP address, hostname, reverse DNS, and FQDN of the target      |
| `2`    | Nmap Port Scan            | Runs Nmap with `-T4` flag to detect open TCP ports                       |
| `3`    | Service Version Detection | Runs Nmap with `-sV` to identify running services and their versions     |
| `4`    | Banner Grabbing           | Connects to common ports via raw socket and reads service banners        |
| `5`    | DNS Lookup                | Resolves DNS records using `nslookup` / `dig` / Python socket fallback   |
| `6`    | Whois Lookup              | Retrieves domain/IP registration information using `whois`               |
| `7`    | Network Ping Sweep        | Runs `nmap -sn` on the `/24` subnet to discover all live hosts           |
| `8`    | Vulnerability Scan        | Runs Nmap vulnerability NSE scripts (`--script=vuln`)                    |
| `9`    | OS Detection              | Uses Nmap `-O` flag to fingerprint the target operating system           |
| `M`    | Mitigation Report         | Scans open ports and generates a risk-rated remediation strategy report  |
| `A`    | Comprehensive Scan        | Executes all modules sequentially in one full assessment                 |

---

## 6.1 Mitigation Strategy Module

The **Mitigation Report** module (option `M`) is a key differentiator of this tool. After scanning the target for open ports, it:

1. **Identifies each open port** and maps it to a known service
2. **Assigns a risk level** (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`) to each service
3. **Lists specific security issues** associated with the service
4. **Provides actionable remediation steps** including:
   - Configuration changes (e.g., disable root SSH login, bind MySQL to localhost)
   - Firewall rules (iptables/ufw commands)
   - Service replacement recommendations (e.g., replace Telnet with SSH)
   - Software update guidance
5. **Generates a summary** with general hardening recommendations

### Risk Level Classification

| Risk Level | Services / Ports Covered |
|------------|--------------------------|
| **CRITICAL** | Telnet (23), NetBIOS/SMB (139), SMB (445), VNC (5900) |
| **HIGH**     | FTP (21), SMTP (25), HTTP (80), POP3 (110), RPCbind (111), IMAP (143), MySQL (3306), PostgreSQL (5432), IRC (6667), HTTP-Alt (8080) |
| **MEDIUM**   | SSH (22), DNS (53), HTTPS-Alt (8443) |
| **LOW**      | HTTPS (443) |

---

## 7. Installation & Usage

### 7.1 Prerequisites (on Kali Linux)

```bash
# Nmap (usually pre-installed on Kali)
sudo apt install nmap

# Whois (usually pre-installed on Kali)
sudo apt install whois

# Python 3 (pre-installed on Kali)
python3 --version
```

### 7.2 Running the Tool

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

### 7.3 Usage Steps

1. Launch the tool: `python3 vapt_suite.py`
2. Enter the target IP address (e.g., the Metasploitable IP: `192.168.x.x`)
3. Select a scan module from the menu (`1`–`9`, `M` for mitigation, `A` for all)
4. Review the color-coded results displayed in the terminal
5. Run the **Mitigation Report** (`M`) to get remediation strategies per discovered port
6. Press **Enter** to return to the menu after each scan
7. Press `B` to change the target, or `Q` to quit

### 7.4 Example Session

```
$ python3 vapt_suite.py

  ╔══════════════════════════════════════════════════════════╗
  ║              Mini VAPT Suite v2.0                       ║
  ║   Vulnerability Assessment and Penetration Testing      ║
  ╚══════════════════════════════════════════════════════════╝

  [#] Enter the target IP or hostname: 192.168.1.105
  [i] Target resolved: 192.168.1.105 → 192.168.1.105

  Select a scan option: M    ← Mitigation Report

  [i] Scanning 192.168.1.105 for open ports...
  [i] Found 8 open port(s): 21, 22, 23, 80, 139, 3306, 5900, 6667

  ┌──────────────────────────────────────────────────────┐
  │  Port 23 — Telnet  |  Risk: CRITICAL
  └──────────────────────────────────────────────────────┘
    Issues:
    • All data transmitted in plaintext (including passwords)
    • No encryption whatsoever
    • Easily sniffable on the network

    Recommended Mitigations:
    1. DISABLE Telnet immediately — it should never be used
    2. Replace with SSH for all remote access needs
    3. Remove telnet daemon: 'sudo apt remove telnetd'
    ...
```

---

## 8. Expected Findings on Metasploitable 2

When the tool is run against **Metasploitable 2**, the expected open ports and corresponding assessments are:

| Port | Service     | Risk Level | Key Finding |
|------|-------------|------------|-------------|
| 21   | FTP         | HIGH       | Anonymous login enabled; vsftpd 2.3.4 backdoor |
| 22   | SSH         | MEDIUM     | OpenSSH — weak password brute-force possible |
| 23   | Telnet      | CRITICAL   | Plaintext transmission; no encryption |
| 25   | SMTP        | HIGH       | Open relay possible; user enumeration |
| 80   | HTTP        | HIGH       | DVWA (Damn Vulnerable Web App) running |
| 139  | NetBIOS     | CRITICAL   | SMBv1 active — EternalBlue potential |
| 445  | SMB         | CRITICAL   | Direct SMB — ransomware vector |
| 3306 | MySQL       | HIGH       | Database exposed; default credentials |
| 5432 | PostgreSQL  | HIGH       | Database network-exposed |
| 5900 | VNC         | CRITICAL   | Weak/no auth; unencrypted desktop access |
| 6667 | IRC         | HIGH       | UnrealIRCd backdoor present |

---

## 9. Disclaimer

> **This tool is developed strictly for educational purposes and should only be used in a controlled lab environment (Kali Linux → Metasploitable 2 on VMware).**
>
> Unauthorized scanning of systems you do not own or have explicit permission to test is **illegal** and may violate laws such as the Computer Fraud and Abuse Act (CFAA). The developers assume no responsibility for misuse.

---

*Mini VAPT Suite — Developed for academic and educational purposes only.*
