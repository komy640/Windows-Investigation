# Windows Investigation Repository

<p align="center">
  <img src="https://github.com/user-attachments/assets/6cc2e947-e9bf-4a86-b92e-cc0d9940a5fb" width="90%">
</p>

## Investigating Windows Threats by Using Event Logs

In the rapidly evolving landscape of cybersecurity, Windows systems are frequently targeted by increasingly sophisticated threats, posing a challenge for SOC analysts in their detection and response efforts. However, Windows event logs offer a critical source of information that can be leveraged to identify security threats and conduct thorough investigations. This repository provides a comprehensive overview of the various types of Windows event logs, delving into the techniques employed by threat actors to compromise these systems, and equipping you with the necessary knowledge to investigate these threats using event logs effectively.

## Table of Contents

- [Introduction to Windows Event Logs](#introduction-to-windows-event-logs)
- [Tracking Accounts Login and Management](#tracking-accounts-login-and-management)
- [Investigating Suspicious Process Execution Using Windows Event Logs](#investigating-suspicious-process-execution-using-windows-event-logs)
- [Investigating PowerShell Event Logs](#investigating-powershell-event-logs)
- [Investigating Persistence and Lateral Movement Using Windows Event Logs](#investigating-persistence-and-lateral-movement-using-windows-event-logs)

---

## Introduction to Windows Event Logs

### Overview
Windows event logs serve as a crucial component for system monitoring, security analysis, and forensic investigations. These logs provide detailed records of system, security, and application activities, enabling administrators and security professionals to detect potential threats and troubleshoot system issues.

### Structure of Windows Event Logs
Windows event logs are categorized into several key log types:
![WhatsApp Image 2025-02-23 at 10 02 46_b54663db](https://github.com/user-attachments/assets/8bdadde5-4654-4610-b6b9-44e9918cda03)


### Key Event Log Sources and IDs
Understanding critical Event IDs can help identify potential security incidents. Some notable examples include:
- **4624** – Successful login
- **4625** – Failed login attempt
- **4688** – Process creation
- **4720** – User account creation
- **7045** – Service installation
- **1102** – Security log cleared

### Configuring and Collecting Event Logs
To effectively monitor Windows event logs, organizations should:
- Enable necessary audit policies via Group Policy or Local Security Policy.
- Use **Windows Event Viewer** for real-time log analysis.
- Deploy **Windows Event Forwarding (WEF)** to centralize log collection.
- Integrate logs with **SIEM solutions** like Splunk, QRadar, or ELK Stack for advanced threat detection.

## Tracking Accounts Login and Management

### Overview
Account login and management events are crucial for detecting unauthorized access. This section covers:
- Event IDs for login success and failures
- Monitoring privilege escalation attempts
- Investigating account management activities

## Investigating Suspicious Process Execution Using Windows Event Logs

### Overview
Processes executed on a system can reveal malicious activities. This section covers:
- Detecting abnormal process executions
- Event IDs related to process creation and termination
- Investigating malware execution patterns

## Investigating PowerShell Event Logs

### Overview
PowerShell is frequently used in cyber attacks. This section covers:
- Logging and analyzing PowerShell commands
- Detecting obfuscated and malicious scripts
- Event IDs related to PowerShell activities

## Investigating Persistence and Lateral Movement Using Windows Event Logs

### Overview
Threat actors use persistence techniques and lateral movement for prolonged access. This section covers:
- Identifying registry-based persistence
- Detecting scheduled tasks and services used for persistence
- Tracking lateral movement within a network

---

## Contributors
- Your Name (@yourgithub)
- Other Contributors

## License
This project is licensed under the MIT License - see the LICENSE file for details.
