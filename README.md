# Windows Investigation Repository

![Windows Investigation](assets/windows-investigation.png)

## Summary

This repository is designed as an informational resource for professionals looking to understand Windows forensic investigation techniques. It provides details on key tactics, tools, and procedures (TTPs) for log analysis, memory forensics, persistence detection, and attack mitigation.

## Table of Contents

- [System Information Gathering](#system-information-gathering)
- [Event Log Analysis](#event-log-analysis)
- [Process and Memory Analysis](#process-and-memory-analysis)
- [Network Traffic Analysis](#network-traffic-analysis)
- [Persistence Mechanisms](#persistence-mechanisms)
- [Defense and Detection](#defense-and-detection)

---

## System Information Gathering

### Commands and Tools:
- `systeminfo` - Gather system details
- `wmic os get caption, version, architecture`
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

