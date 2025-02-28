# Windows Investigation 

<p align="center">
  <img src="https://github.com/user-attachments/assets/6cc2e947-e9bf-4a86-b92e-cc0d9940a5fb" width="90%">
</p>

## Investigating Windows Threats Using Event Logs

In the rapidly evolving landscape of cybersecurity, Windows systems are frequently targeted by increasingly sophisticated threats, posing a challenge for SOC analysts in their detection and response efforts. However, Windows event logs offer a critical source of information that can be leveraged to identify security threats and conduct thorough investigations. This repository provides a comprehensive overview of the various types of Windows event logs, delving into the techniques employed by threat actors to compromise these systems, and equipping you with the necessary knowledge to investigate these threats using event logs effectively.

## Table of Contents

- [Introduction to Windows Event Logs](#introduction-to-windows-event-logs)
- [Tracking Accounts Login and Management](#tracking-accounts-login-and-management)
- [Investigating Suspicious Process Execution Using Windows Event Logs](#investigating-suspicious-process-execution-using-windows-event-logs)
- [Investigating PowerShell Event Logs](#investigating-powershell-event-logs)
- [Investigating Persistence Using Windows Event Logs](#investigating-persistence-using-windows-event-logs)
- [Investigating Lateral Movement Using Windows Event Logs](#investigating-lateral-movement-using-windows-event-logs)

---

## Introduction to Windows Event Logs

### Overview
Windows event logs serve as a crucial component for system monitoring, security analysis, and forensic investigations. These logs provide detailed records of system, security, and application activities, enabling administrators and security professionals to detect potential threats and troubleshoot system issues.

### Structure of Windows Event Logs
Windows event logs are categorized into several key log types:

![WhatsApp Image 2025-02-23 at 10 02 46_b54663db](https://github.com/user-attachments/assets/8bdadde5-4654-4610-b6b9-44e9918cda03)


### The Important Tools to Investigate in Windows Logs
To efficiently analyze Windows logs, security professionals leverage various tools, including:
- **Event Viewer** – A built-in tool for viewing and filtering Windows event logs.
- **PsLogList** – A command-line utility for listing event logs remotely.
- **Event Log Explorer** – A third-party tool for advanced log analysis.
- **EvtxECmd** – A powerful tool for parsing and analyzing Windows event log files.
- **SIEM (Security Information and Event Management)** – Solutions like Splunk, QRadar, and ELK for centralized log analysis and threat detection.



## Tracking Accounts Login and Management

### Overview
Account login and management events are crucial for detecting unauthorized access. This section covers:
- Windows accounts
- Account login tracking
- Investigating account management activities


### Windows accounts:
![WhatsApp Image 2025-02-25 at 08 02 59_a05a2460](https://github.com/user-attachments/assets/32007c6b-5b0e-4679-a22f-454060f8c1f5)

### Account login tracking
![WhatsApp Image 2025-02-25 at 09 53 08_5af79ee1](https://github.com/user-attachments/assets/463bb4fb-d545-43b5-9a67-15b3d2e90f46)



### Account Management Events
The following table lists critical event IDs related to user account activities:

| Event ID | Event Name |
|----------|----------------------------------|
| 4720     | A user account was created |
| 4722     | A user account was enabled |
| 4723     | An attempt was made to change an account’s password |
| 4724     | An attempt was made to reset an account’s password |
| 4725     | A user account was disabled |
| 4726     | A user account was deleted |
| 4738     | A user account was changed |
| 4740     | A user account was locked out |
| 4767     | A user account was unlocked |


the most important code to focus on is the (event id 4720) becouse the attacker maybe create a new account as a presistence technique

### Group Membership and Account Management Event IDs

| Event ID | Description |
|----------|--------------------------------------------|
| 4720     | User account creation |
| 4728     | A member was added to a security-enabled global group |
| 4729     | A member was removed from a security-enabled global group |
| 4732     | A member was added to a security-enabled local group |
| 4733     | A member was removed from a security-enabled local group |
| 4756     | A member was added to a security-enabled universal group |
| 4757     | A member was removed from a security-enabled universal group |
| 4727     | A security-enabled global group was created |
| 4730     | A security-enabled global group was deleted |
| 4731     | A security-enabled local group was created |
| 4734     | A security-enabled local group was deleted |
| 4754     | A security-enabled universal group was created |
| 4758     | A security-enabled universal group was deleted |





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

## Investigating Persistence Using Windows Event Logs

This section will explain some persistence techniques and how to investigate them using Windows event logs. For each technique, we will describe how it works and analyze the relevant Windows event logs that can help in investigations.

### 1. Registry Run Keys
Attackers add malware execution paths to Windows registry keys to maintain persistence.
- **Event Logs to Monitor:**
  - Event ID **4657** (Registry modifications)
  - Event ID **4663** (Registry object access)

### 2. Windows Scheduled Tasks
Scheduled tasks allow attackers to execute payloads at specific times or during system events.
- **Event Logs to Monitor:**
  - Event ID **4698** (Scheduled task created)
  - Event ID **4699** (Scheduled task deleted)
  - Event ID **4700** (Scheduled task enabled)

### 3. Windows Services
Malicious services are installed to execute malware with system privileges.
- **Event Logs to Monitor:**
  - Event ID **7045** (New service installation)
  - Event ID **7034** (Service crashed unexpectedly)

### 4. WMI Event Subscription
Windows Management Instrumentation (WMI) is used by attackers to trigger malicious code execution.
- **Event Logs to Monitor:**
  - Event ID **5861** (WMI filter created)
  - Event ID **5860** (WMI consumer registered)

By tracking these event logs, security analysts can detect and investigate persistence mechanisms used by adversaries, helping mitigate threats effectively.


## Investigating Lateral Movement Using Windows Event Logs

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
