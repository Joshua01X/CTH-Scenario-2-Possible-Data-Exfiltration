# Threat Hunting: Investigating Possible Data Exfiltration

## Introduction/Objectives
This project focuses on threat hunting in a cloud-hosted environment, specifically investigating devices exposed to the internet for potential data exfiltration. Leveraging Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL), the analysis aims to detect suspicious activities, unauthorized access attempts, and potential data leaks. The primary goal is to identify Indicators of Compromise (IoCs) and evaluate whether any sensitive data has been exfiltrated.

## Components, Tools, and Technologies Employed
- **Cloud Environment:** Microsoft Azure (VM-hosted threat-hunting lab)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
- **Query Language:** Kusto Query Language (KQL) for log analysis

## Disclaimer
This investigation takes place in a shared learning environment within the same Microsoft Azure subscription. As a result, logs may contain unrelated failed login attempts or activities from other internal private IP addresses. The primary focus of this project is on remote threat actors—external IP addresses exhibiting suspicious behaviors, particularly those unaffiliated with the Azure company subscription.

## Scenario
A virtual machine hosted in Microsoft Azure is exposed to the internet, allowing remote access. The objective of this investigation is to identify whether unauthorized access attempts occurred and to track potential data exfiltration activities. Using Microsoft Defender for Endpoint, logs will be analyzed to uncover any suspicious behavior, including file manipulation, unauthorized software installations, and outbound connections to untrusted IP addresses.

## High-Level IoC Discovery Plan
1. Identify file-related activities involving archives, particularly `.zip` files.
2. Track the execution of processes that could indicate unauthorized software installation.
3. Examine network activities for signs of remote access attempts or data exfiltration.
4. Investigate logon events to determine if unauthorized users attempted access.
5. Correlate findings to assess whether data exfiltration has occurred.

## Steps Taken

### STEP 1: File Activity Investigation
Performed a search within MDE's `DeviceFileEvents` to identify `.zip` file-related activities. The results revealed regular archiving activities, where files were created and renamed in a "backup" folder.

#### KQL Query Used:
```kql
DeviceFileEvents
| where DeviceName == "windows-target-1"
| where FileName endswith ".zip"
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/221e0ac1-c475-43c8-bf14-264cdc2cede9)


### STEP 2: Process Execution Analysis
A deeper investigation was conducted by extracting a timestamp from one of the `.zip` file creation events. A follow-up query searched for process activities occurring within a two-minute window before and after the event. This analysis revealed that a PowerShell script silently installed 7zip and then used it to archive employee data.

#### KQL Query Used:
```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-01-27T23:48:58.8234341Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/d6f03f14-6df1-463b-99b2-793055959e49)


### STEP 3:  Network Activity Investigation
To assess whether data exfiltration occurred, a broader search was performed, analyzing network events five minutes before and after the identified incident.

Findings:
- An RDP session was initiated from a public IP address (`185.42.12.42`), suggesting a potential unauthorized access attempt.
- An outbound HTTPS connection was made to an Azure-associated IP (`20.189.173.16`), raising concerns about data exfiltration or command-and-control activity.
- An inbound connection to the print spooler service (`spoolsv.exe`) was detected, which could indicate an exploitation attempt.

#### KQL Query Used:
```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-01-27T23:48:58.8234341Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
| where DeviceName == VMName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/d511548e-402c-47a0-b5f4-b997dba732b2)


### STEP 4: Logon Event Investigation
Further analysis was conducted on the IP associated with the RDP session to determine if successful authentication occurred. The query returned no results, indicating that the IP attempted network-level communication but did not successfully log in.

#### KQL Query Used:
```kql
DeviceLogonEvents
| where RemoteIP contains "185.42.12.42"
```
![image](https://github.com/user-attachments/assets/7d18e127-de57-468f-aca6-ec8b2faea463)


### STEP 5: Microsoft Azure IP Analysis
The outbound connection to `20.189.173.16` was found to belong to Microsoft's Azure infrastructure (AS8075). This suggests the connection is likely related to legitimate Microsoft services, such as Windows Update or Azure-related processes.

#### KQL Query Used:
```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-01-27T23:48:58.8234341Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
| where DeviceName == "windows-target-1"
| where RemoteIP == "20.189.173.16" and RemotePort == 443
| project Timestamp, DeviceName, RemoteIP, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```
![image](https://github.com/user-attachments/assets/5680e1a4-56bf-46f9-83c4-37acc8668c67)


## Response
Findings were reported to the employee's manager, highlighting the automation of archive creation via PowerShell scripts. No conclusive evidence of data exfiltration was found, but monitoring remains in place for further instructions from management.

## Tactics, Techniques, and Procedures (TTPs) from MITRE ATT&CK Framework
- **T1071.001** - Application Layer Protocol: Web Protocols (HTTPS)
- **T1071.004** - Application Layer Protocol: Remote Desktop Protocol (RDP)
- **T1105** - Remote File Copy
- **T1070.001** - Indicator Removal from Tools: File Deletion
- **T1074** - Data Staged
- **T1021.001** - Remote Services: Remote Desktop Protocol (RDP)
- **T1134.002** - Access Token Manipulation: Token Impersonation
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1011** - Exfiltration Over Other Network Medium
- **T1057** - Process Discovery
- **T1064** - Scripting

