# Windows Investigation Repository

<p align="center">
  <img src="https://github.com/user-attachments/assets/6cc2e947-e9bf-4a86-b92e-cc0d9940a5fb" width="90%">
</p>

## Investigating Windows Threats by Using Event Logs

In the rapidly evolving landscape of cybersecurity, Windows systems are frequently targeted by increasingly sophisticated threats, posing a challenge for SOC analysts in their detection and response efforts. However, Windows event logs offer a critical source of information that can be leveraged to identify security threats and conduct thorough investigations. This repository provides a comprehensive overview of the various types of Windows event logs, delving into the techniques employed by threat actors to compromise these systems, and equipping you with the necessary knowledge to investigate these threats using event logs effectively.

## Table of Contents

- [Chapter 3: Introduction to Windows Event Logs](#chapter-3-introduction-to-windows-event-logs)
- [Chapter 4: Tracking Accounts Login and Management](#chapter-4-tracking-accounts-login-and-management)
- [Chapter 5: Investigating Suspicious Process Execution Using Windows Event Logs](#chapter-5-investigating-suspicious-process-execution-using-windows-event-logs)
- [Chapter 6: Investigating PowerShell Event Logs](#chapter-6-investigating-powershell-event-logs)
- [Chapter 7: Investigating Persistence and Lateral Movement Using Windows Event Logs](#chapter-7-investigating-persistence-and-lateral-movement-using-windows-event-logs)

---

## Chapter 3: Introduction to Windows Event Logs

### Overview
Windows event logs are a valuable resource for security monitoring and forensic investigations. This chapter covers:
- Understanding Windows event logs structure
- Key event IDs and log sources
- Configuring and collecting event logs efficiently

## Chapter 4: Tracking Accounts Login and Management

### Overview
Account login and management events are crucial for detecting unauthorized access. This chapter covers:
- Event IDs for login success and failures
- Monitoring privilege escalation attempts
- Investigating account management activities

## Chapter 5: Investigating Suspicious Process Execution Using Windows Event Logs

### Overview
Processes executed on a system can reveal malicious activities. This chapter covers:
- Detecting abnormal process executions
- Event IDs related to process creation and termination
- Investigating malware execution patterns

## Chapter 6: Investigating PowerShell Event Logs

### Overview
PowerShell is frequently used in cyber attacks. This chapter covers:
- Logging and analyzing PowerShell commands
- Detecting obfuscated and malicious scripts
- Event IDs related to PowerShell activities

## Chapter 7: Investigating Persistence and Lateral Movement Using Windows Event Logs

### Overview
Threat actors use persistence techniques and lateral movement for prolonged access. This chapter covers:
- Identifying registry-based persistence
- Detecting scheduled tasks and services used for persistence
- Tracking lateral movement within a network

---

## Contributors
- Your Name (@yourgithub)
- Other Contributors

## License
This project is licensed under the MIT License - see the LICENSE file for details.
