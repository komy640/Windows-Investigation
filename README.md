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


## Investigating PowerShell Event Logs

## Investigating Persistence Using Windows Event Logs

This section will explain some persistence techniques and how to investigate them using Windows event logs. For each technique, we will describe how it works and analyze the relevant Windows event logs that can help in investigations.

### 1. Registry Run Keys
The Windows Registry is a hierarchical database that stores configuration settings, options, and information about the operating system, hardware devices, software applications, and user preferences on Microsoft Windows operating systems. It serves as a central repository for critical system and application settings.

The Registry consists of five hives, with the most important ones being:
- **HKEY_CURRENT_USER (HKCU):** Stores configuration settings for the currently logged-in user.
- **HKEY_LOCAL_MACHINE (HKLM):** Stores configuration settings for the entire computer system, applicable to all users.

Each registry hive includes several registry keys, such as the **registry run keys**. Registry run keys enable a program to execute when a user logs on to a system. Attackers may achieve persistence by modifying or adding new values under these registry run keys, referencing a malware path to be executed upon user login. This can be done using the Windows built-in **Registry Editor GUI tool** or a **command-line tool** such as the Windows built-in `reg.exe` tool.

The following registry run keys exist by default in Windows OS:
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`

#### Example of a Malicious Registry Entry

A new registry value **Malware** is created under one of the registry run keys, referencing the `C:\Windows\Temp\Malware.exe` executable path to execute upon user login.

#### Investigating Registry Run Key Modifications

Microsoft provides event logs that help in detecting suspicious access, additions, or modifications to registry keys, including registry run keys. The following event IDs are useful for investigation:

| Event ID | Event Name |
|----------|------------------------------------------------|
| 4656     | A handle to an object was requested          |
| 4657     | A registry value was modified                |
| 4658     | The handle to an object was closed          |
| 4660     | An object was deleted                        |
| 4663     | An attempt was made to access an object     |

Most of these event names refer to an object, except for **event ID 4657**, which explicitly refers to registry modifications. The other event IDs record general access to objects, including registry keys.



### 2. Windows Scheduled Tasks
Windows Scheduled Tasks are predefined recurring actions that execute automatically when specific conditions are met. Attackers may achieve persistence by creating a scheduled task to execute malicious code repeatedly.

A scheduled task can be created via the GUI tool or command-line tools such as `schtasks.exe`:

```sh
schtasks /create /tn mysc /tr C:\Users\Public\test.exe /sc ONLOGON /ru System
```

The command above was executed by the APT3 group to create a scheduled task named `mysc` that executes `C:\Users\Public\test.exe` every time a user logs in under the **System** account.

#### Investigating Scheduled Task Persistence

Microsoft allows tracking scheduled task creation via **event ID 4698** ("A scheduled task was created") in the **Security** event log.

Key investigation details from event ID **4698**:
- **Subject Section** – Identifies the user who created the task.
- **Task Information Section** – Provides details such as:
  - **Task Name**: The assigned name of the scheduled task.
  - **Task Content**: Contains XML-formatted task details, including execution time and the command to run.

Example of a suspicious scheduled task:
- The scheduled task `MordorSchtask` executes PowerShell every day at `2020-09-21T09:00:00`.
- The command executed is:
  ```sh
  powershell.exe -NonI -W hidden -c IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))
  ```
  - This indicates **fileless attack behavior**, executing an encoded command stored in the registry.
- The task runs under the compromised account `THESHIRE\pgustavo`.

#### Detecting Anomalous Scheduled Tasks

To identify malicious scheduled tasks, look for:
- **Scheduled tasks created outside normal working hours.**
- **Tasks executing suspicious processes** (e.g., binaries from user profiles or temp paths).
- **Execution of Living-Off-The-Land Binaries (LOLBins)**, such as:
  - PowerShell (`powershell.exe`)
  - Command Prompt (`cmd.exe`)
  - Rundll32 (`rundll32.exe`)
- **Compromised accounts used to create or execute scheduled tasks.**
## Understanding and Investigating Persistence Techniques

### Registry Run Keys

The Windows Registry is a hierarchical database that stores configuration settings, options, and information about the operating system, hardware devices, software applications, and user preferences on Microsoft Windows operating systems. It serves as a central repository for critical system and application settings.

The Registry consists of five hives, with the most important ones being:
- **HKEY_CURRENT_USER (HKCU):** Stores configuration settings for the currently logged-in user.
- **HKEY_LOCAL_MACHINE (HKLM):** Stores configuration settings for the entire computer system, applicable to all users.

Each registry hive includes several registry keys, such as the **registry run keys**. Registry run keys enable a program to execute when a user logs on to a system. Attackers may achieve persistence by modifying or adding new values under these registry run keys, referencing a malware path to be executed upon user login. This can be done using the Windows built-in **Registry Editor GUI tool** or a **command-line tool** such as the Windows built-in `reg.exe` tool.

The following registry run keys exist by default in Windows OS:
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`

#### Example of a Malicious Registry Entry

A new registry value **Malware** is created under one of the registry run keys, referencing the `C:\Windows\Temp\Malware.exe` executable path to execute upon user login.

#### Investigating Registry Run Key Modifications

Microsoft provides event logs that help in detecting suspicious access, additions, or modifications to registry keys, including registry run keys. The following event IDs are useful for investigation:

| Event ID | Event Name |
|----------|------------------------------------------------|
| 4656     | A handle to an object was requested          |
| 4657     | A registry value was modified                |
| 4658     | The handle to an object was closed          |
| 4660     | An object was deleted                        |
| 4663     | An attempt was made to access an object     |

Most of these event names refer to an object, except for **event ID 4657**, which explicitly refers to registry modifications. The other event IDs record general access to objects, including registry keys.

#### Analyzing Event ID 4656: "A Handle to an Object Was Requested"

Event ID **4656** consists of four key sections:
1. **Subject Section** – Information about the user who performed the action.
2. **Object Section** – Details about the accessed object:
   - `Object Server`: Always "Security"
   - `Object Type`: Could be a file, key, or SAM (for registry run key persistence, focus on "Key")
   - `Object Name`: The accessed registry key path
3. **Process Information Section** – The process that performed the action.
4. **Access Request Information Section** – Permissions (not always useful for investigations).

#### Detecting Suspicious Registry Modifications

Abnormal access by processes like **PowerShell.exe** or **CMD.exe** to registry run keys can be a sign of persistence. In one example, event logs recorded PowerShell modifying the `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` key under the context of user `pgustavo`. While event ID **4656** does not directly provide details on newly added values, it helps identify suspicious registry access patterns.

To detect new or modified registry values, use **event ID 4657** ("A registry value was modified"). However, note that **registry modification auditing is not enabled by default**. To generate event ID 4657, the **Set Value auditing** must be configured in the registry key’s **System Access Control List (SACL)**.

### Windows Scheduled Tasks

Windows Scheduled Tasks are predefined recurring actions that execute automatically when specific conditions are met. Attackers may achieve persistence by creating a scheduled task to execute malicious code repeatedly.

A scheduled task can be created via the GUI tool or command-line tools such as `schtasks.exe`:

```sh
schtasks /create /tn mysc /tr C:\Users\Public\test.exe /sc ONLOGON /ru System
```

The command above was executed by the APT3 group to create a scheduled task named `mysc` that executes `C:\Users\Public\test.exe` every time a user logs in under the **System** account.

#### Investigating Scheduled Task Persistence

Microsoft allows tracking scheduled task creation via **event ID 4698** ("A scheduled task was created") in the **Security** event log.

Key investigation details from event ID **4698**:
- **Subject Section** – Identifies the user who created the task.
- **Task Information Section** – Provides details such as:
  - **Task Name**: The assigned name of the scheduled task.
  - **Task Content**: Contains XML-formatted task details, including execution time and the command to run.

Example of a suspicious scheduled task:
- The scheduled task `MordorSchtask` executes PowerShell every day at `2020-09-21T09:00:00`.
- The command executed is:
  ```sh
  powershell.exe -NonI -W hidden -c IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))
  ```
  - This indicates **fileless attack behavior**, executing an encoded command stored in the registry.
- The task runs under the compromised account `THESHIRE\pgustavo`.

#### Detecting Anomalous Scheduled Tasks

To identify malicious scheduled tasks, look for:
- **Scheduled tasks created outside normal working hours.**
- **Tasks executing suspicious processes** (e.g., binaries from user profiles or temp paths).
- **Execution of Living-Off-The-Land Binaries (LOLBins)**, such as:
  - PowerShell (`powershell.exe`)
  - Command Prompt (`cmd.exe`)
  - Rundll32 (`rundll32.exe`)
- **Compromised accounts used to create or execute scheduled tasks.**

### Important Event IDs Related to Services

| Event ID | Event Name |
|----------|------------------------------------------------|
| 4697     | A service was installed in the system         |
| 7045     | A new service was installed                   |
| 7036     | A service changed state (started/stopped)     |
| 7024     | A service terminated unexpectedly            |
| 6005     | The event log service was started            |
| 6006     | The event log service was stopped            |

Tracking service-related events is crucial to identifying unauthorized or malicious service installations and modifications.



### 3. Windows Services
A Windows service is a process that runs in the background without user interaction and can start even before a user logs in. Attackers may achieve persistence by creating a new service or modifying an existing one to execute malicious code.

#### Example: Creating a Malicious Service

```sh
sc.exe create TestService binpath= c:\windows\temp\NewServ.exe start= auto
```

This command creates a service named **TestService** that executes `c:\windows\temp\NewServ.exe` automatically on startup.

#### Investigating Service Creation

Microsoft logs service creation events with **event ID 7045** (System logs) and **event ID 4697** (Security logs). Key fields include:
- **Service Name** – The newly created service name.
- **Service File Name** – The binary path executed.
- **Service Start Type**:
  - `0`: Boot device services
  - `1`: Driver started by I/O subsystem
  - `2`: **Auto-start (commonly used by attackers)**
  - `3`: Manual start
  - `4`: Disabled
- **Service Account** – The account context under which the service runs.
  
Malicious services are installed to execute malware with system privileges.
- **Event Logs to Monitor:**
  - Event ID **7045** (New service installation)
  - Event ID **7034** (Service crashed unexpectedly)

### 4. WMI Event Subscription
An attacker may keep persistence on an infected system by configuring the Windows Management Instrumentation (WMI) event subscription to execute malicious content, either through a script or the command line, when specific conditions are met.

To keep persistence on the victim's machine by using WMI event subscription, an attacker needs to conduct the following three steps:
1. **Create an Event Filter:** Defines a specific trigger condition (e.g., every one minute).
2. **Create an Event Consumer:** Defines the script or command that should be executed once the condition in the event filter is met.
3. **Create a Binding:** Ties the event filter and event consumer together.

Microsoft provides **event ID 5861** in the `Microsoft-Windows-WMI-Activity/Operational` log file, which records every WMI event consumer creation activity, allowing investigation of suspicious WMI consumer creation behavior.

#### Investigating Suspicious WMI Consumer Creation

Event ID **5861** provides crucial information for threat investigators and hunters to detect and investigate suspicious WMI event consumer creation activities. This event shows that a new WMI event consumer named **Updater** was created, bound to an event filter (also named **Updater**), and configured as a **CommandLineEventConsumer** executing a suspiciously encoded PowerShell command.

The types of WMI event consumers that can be used maliciously are:
- **CommandLineEventConsumer:** Executes commands.
- **ActiveScriptEventConsumer:** Executes scripts.

To investigate suspicious consumer creation:
- Identify whether the consumer type is **CommandLineEventConsumer** or **ActiveScriptEventConsumer**.
- Investigate rare WMI event filter and consumer names.
- Determine whether the consumer executes suspicious actions, such as running a binary from an unusual path or leveraging a **living-off-the-land binary (LOLBIN)**.

### Summary

By leveraging Windows Event Logs, security analysts can detect persistence mechanisms, including:
- **Registry modifications (`4656, 4657`)**
- **Scheduled tasks (`4698`)**
- **Service installations (`4697, 7045`)**
- **WMI event subscriptions (`5861`)**

In the next section, we will discuss some lateral movement techniques and how to investigate them by analyzing the Windows event logs of both source and target machines.


## Investigating Lateral Movement Using Windows Event Logs

Lateral movement refers to the techniques that an attacker conducts after gaining initial access to a system and discovering the victim's network, to pivoting from the compromised machine to another machine in the same network to search for sensitive data and high-value systems. 

To move from one machine to another, the attacker must use one of several lateral movement techniques, such as:
- Remote Desktop application
- PowerShell remoting
- The PsExec tool
- Remote admin share
- Creating a remote service or scheduled task

In this section, we will deep dive into the following lateral movement techniques:
- **Remote Desktop application**
- **Windows admin shares**
- **The PsExec Sysinternals tool**
- **PowerShell remoting**

We will also discuss how to investigate these techniques by analyzing Windows event logs recorded on both source and target machines.

### Remote Desktop Connection

Attackers can use the built-in Windows Remote Desktop connection tool to fully access and control remote systems in a network for lateral movement. RDP traffic is often considered legitimate and permitted by security devices, making it an attractive technique for attackers.

To investigate RDP lateral movement, analysts can utilize Windows event logs recorded on both the source and target machines:
- **Source machine logs:** Event ID 4688 (execution of `mstsc.exe`)
- **Target machine logs:**
  - Event ID 4688 (`rdpclip.exe`, `tstheme.exe` execution)
  - Event ID 4624 (successful RDP authentication, login type 10)
  - Event ID 4778 (reconnected RDP session)
  - Event ID 4779 (disconnected RDP session)

### Windows Admin Shares Lateral Movement

Windows admin shares, such as `C$` and `ADMIN$`, allow remote access for administrative tasks. Attackers leverage these shares to move laterally across the network, executing commands or transferring files remotely.

To investigate Windows admin share lateral movement:
- **Event ID 5140** - Network share object accessed
- **Event ID 5145** - Detailed share permissions
- **Event ID 4624** - Logon success (Type 3 for network logon)
- **Monitor suspicious access from non-admin users**

Tools such as `psexec.exe`, `wmic`, and `smbexec.py` are commonly used in admin share-based lateral movement.


### PsExec – a Sysinternals Tool

PsExec is a Sysinternals tool developed by Microsoft for remote code execution on other systems. Most attackers use the PsExec tool for both remote code execution and lateral movement. Attackers take advantage of this lightweight, capable tool, including the fact that many system admins use it in their day-to-day operations and that it is digitally signed by Microsoft and not categorized as malware by antiviruses, to stealthily execute their malicious executables remotely.

Before investigating the event log artifacts of the PsExec tool usage, let us first discuss PsExec behavior when used for lateral movement and remote executions.

#### PsExec Remote Code Execution Behavior

The process of PsExec-based lateral movement involves a remote code execution from Host A to Host B. The attacker enters the following command in Host A:

```sh
psexec.exe \\HostB -accepteula -d -c C:\MalwareFolder\malware.exe
```

This command uses the PsExec tool to copy and execute the `Malware.exe` binary, located in Host A in the `C:\MalwareFolder` path, remotely on Host B. If the attacker has proper administrative privileges, executing this command on Host A will authenticate to Host B, and then, by default configuration, the following occurs:

1. The `psexesvc.exe` (to handle the remote execution) and `Malware.exe` (the attacker's malicious executable) binaries will be copied to the `ADMIN$` share on Host B.
2. A Windows service is created and starts executing the `psexesvc.exe` binary to execute the `Malware.exe` binary.
3. The `psexesvc.exe` binary is a renamed copy of the `psexec.exe` binary to handle the remote execution from the source to the remote host.

SOC analysts and incident responders should be aware of the Windows event logs recorded on both source and target machines to detect and investigate suspicious PsExec remote code executions.

#### Investigating PsExec Event Logs

##### Source Machine Event Logs

While most of the PsExec event log artifacts are recorded on the target machine, useful events are also logged on the source system:
- **Event ID 4688:** Records the execution of the `psexec.exe` process, including useful information such as the process name, process path, parent process, and the process command line (if CMD logging is enabled), which allows you to identify the target host of the remote execution.

##### Target Machine Event Logs

The majority of event log artifacts of PsExec remote execution are recorded on the target host. The first recorded event is:
- **Event ID 4624:** Records the successful authentication to the target system to access shared resources (`ADMIN$`). This event provides valuable information such as the login account name, login type (3 or 2 if explicit credentials are provided), the source workstation name, and IP address.
- **Event IDs 5140 and 5145:** Track accessed and mapped shared folders and files of the system, including potentially transferred files.
- **Event ID 7045 and Event ID 4697:** Record the creation of a new service named `PSEXESVC` to execute the `%SystemRoot%\PSEXESVC.exe` binary. The service start type value is `3`, meaning the service will be executed on demand manually.
- **Event ID 4688:** Records the execution of the `PSEXESVC.exe` binary, which is spawned by `Services.exe`, the expected parent process of all services’ binaries.
- **Process ID Tracking:** By tracking spawned processes from the `PSEXESVC.exe` process, analysts may identify additional executed binaries. For example, a `Python.exe` process running from the `C:\Windows\Temp` path may have been spawned by `PSEXESVC.exe`, indicating a potential attack.

While PsExec has several legitimate uses for system administrators, it is also widely used by attackers for lateral movement. To differentiate between legitimate and malicious use of PsExec, it is crucial to establish a baseline for your environment. 

- In environments where system admins frequently use PsExec, observe any suspicious executions by non-admin users or outside normal working hours.
- Focus on executed code and spawned processes by `PSEXESVC.exe` on a remote system.

By understanding PsExec usage and how attackers utilize it for lateral movement, analysts can better detect and investigate suspicious activities. In the next section, we will discuss the PowerShell remoting lateral movement technique and how to investigate its presence using recorded Windows event logs on both source and target machines.


## PowerShell Remoting Lateral Movement



Attackers are heavily dependent on PowerShell to achieve their objectives, including lateral movement. PowerShell is installed by default on all Windows systems, is not flagged as malicious by antivirus software, and provides remote access capabilities over an encrypted channel. Additionally, Windows administrators commonly use PowerShell for daily operations, allowing malicious activity to blend in with legitimate administration tasks.

PowerShell remoting uses the **Windows Remote Management (WinRM)** protocol, which allows users to execute commands on remote systems over an encrypted channel. Attackers can execute commands remotely using the following:

```powershell
Invoke-Command -ComputerName VICTIM -ScriptBlock {Start-Process c:\malwarefolder\malware.exe} -Credential $credentials
```

```powershell
Enter-PSSession -ComputerName VICTIM -Credential $credentials
```

SOC analysts and incident responders should be aware of the relevant Windows event logs recorded on both source and target machines to detect and investigate suspicious PowerShell remoting activities.

### Investigating PowerShell Remoting Event Logs

#### Source Machine Event Logs

Several event logs recorded on the source machine can help investigate PowerShell remoting activities:
- **Event ID 4688:** Logs the execution of the `powershell.exe` process, its command line, and its parent process.
- **Event ID 4104:** Logs executed PowerShell command lines and scripts.
- **Event ID 800:** Captures executed PowerShell commands.

#### Target Machine Event Logs

Like all lateral movement techniques, the most valuable event log artifacts of PowerShell remoting are recorded on the target machine:
- **Event ID 4624:** Logs successful authentication to the target system with **logon type 3**. This event provides details such as the login account name, source workstation name, and IP address.
- **Event ID 4688:** Logs the execution of the `wsmprovhost.exe` process, which is responsible for handling PowerShell remoting sessions.

The `wsmprovhost.exe` process runs on the target system to receive commands from the source machine’s PowerShell session. To monitor these actions effectively, track event ID 4688 for any commands executed or processes spawned from `wsmprovhost.exe` on the target system.

For example, **event ID 4688** may show `wsmprovhost.exe` spawning `powershell.exe` with an encoded command. Since PowerShell logs all executed commands, further investigation using event IDs **800 and 4104** can reveal the full decoded script.

By understanding how attackers use PowerShell remoting for lateral movement and monitoring these event logs, analysts can effectively detect and investigate suspicious activity.





---

## Contact Information
- **LinkedIn:** [Your LinkedIn URL](https://www.linkedin.com/in/ahmed-elkomy-b17946256/]
- **Email:** [alkomyy22@gmail.com]


