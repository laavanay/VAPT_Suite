# Mini VAPT Suite
### Mini Vulnerability Assessment and Penetration Testing Suite

Mini Vulnerability Assessment and Penetration Testing Suite is a simple security tool developed to scan systems and identify potential vulnerabilities such as open ports, insecure services, and weak configurations in a controlled lab environment.

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
- Target Machine – Metasploitable
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

| #  | Module                      | Description                                         |
|----|-----------------------------|-----------------------------------------------------|
| 1  | Basic Information Gathering | IP address, hostname, reverse DNS                   |
| 2  | Nmap Port Scan              | Detects open ports on the target                    |
| 3  | Service Detection           | Identifies running services and their versions      |
| 4  | Banner Grabbing             | Connects to ports and reads service banners         |
| 5  | DNS Lookup                  | Resolves DNS records for the target                 |
| 6  | Whois Lookup                | Domain/IP registration details                      |
| 7  | Network Ping Sweep          | Discovers active hosts on the target subnet         |
| 8  | Vulnerability Scan          | Runs Nmap vulnerability detection scripts           |
| 9  | OS Detection                | Fingerprints the target operating system            |
| A  | Comprehensive Scan          | Runs all modules sequentially                       |

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
cd Mini_VAPT_Suite

# Run the scanner
python3 vapt_suite.py

# Or make it executable and run directly
chmod +x vapt_suite.py
./vapt_suite.py
```

### Usage Steps
1. Launch the tool with `python3 vapt_suite.py`
2. Enter the target IP address or hostname (e.g., `192.168.1.100` or the Metasploitable IP)
3. Select a scan module from the menu (1–9, A for all)
4. Review the results displayed in the terminal
5. Press Enter to return to the menu after each scan

### Example
```
$ python3 vapt_suite.py
  [#] Enter the target IP or hostname: 192.168.1.100
  [i] Target resolved: 192.168.1.100 → 192.168.1.100

  Select a scan option: 2    ← Nmap Port Scan
```

---

## 8. Disclaimer

> **This tool is developed strictly for educational purposes and should only be used in a controlled lab environment.**# VAPT_Suite
