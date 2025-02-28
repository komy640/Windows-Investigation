# Windows Investigation 
<img src="https://github.com/user-attachments/assets/6cc2e947-e9bf-4a86-b92e-cc0d9940a5fb" width="1000" height="500">

## Summary

This repository is designed as an informational resource for professionals looking to understand Windows forensic investigation techniques. It provides details on key tactics, tools, and procedures (TTPs) for log analysis, persistence detection, and attack mitigation.

## Table of Contents

- [Event Logs](#Event-Logs)
- [Event Log Analysis](#event-log-analysis)
- [Process and Memory Analysis](#process-and-memory-analysis)
- [Network Traffic Analysis](#network-traffic-analysis)
- [Persistence Mechanisms](#persistence-mechanisms)
- [Defense and Detection](#defense-and-detection)

---

## Event Logs

### Windows Event Logs:
![WhatsApp Image 2025-02-23 at 10 02 46_08864a13](https://github.com/user-attachments/assets/193092bf-ff35-483b-beea-44ac285203a2)

- `whoami /all` - Get user privileges
- `net users /domain` - Enumerate users

## Event Log Analysis

### Key Windows Event IDs:
- **4624** - Successful Logon
- **4625** - Failed Logon
- **4688** - Process Creation
- **4720** - User Created
- **4728** - User Added to Privileged Group

### Tools:
- Windows Event Viewer (`eventvwr.msc`)
- PowerShell: `Get-WinEvent -LogName Security | select -First 10`

## Process and Memory Analysis

### Commands:
- `tasklist /v` - View running processes
- `wmic process get description,executablepath`
- `procdump` - Capture memory dump

### Tools:
- Sysinternals Suite
- Volatility Framework

## Network Traffic Analysis

### Commands:
- `netstat -ano` - View active connections
- `ipconfig /all` - Network configuration

### Tools:
- Wireshark
- TCPDump
- Microsoft Message Analyzer

## Persistence Mechanisms

### Registry Persistence:
- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

### Scheduled Tasks:
- `schtasks /query /fo LIST /v`

## Defense and Detection

- Enable Windows Defender ATP
- Configure Sysmon for logging
- Use YARA rules for malware detection
- SIEM Integration (Splunk, ELK, QRadar)

---

## Contributors
- Your Name (@yourgithub)
- Other Contributors

