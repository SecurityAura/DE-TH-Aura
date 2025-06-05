# *Windows Services*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/05 | Initial version (Query #1 to #6) |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1569.002 | System Services: Service Execution | https://attack.mitre.org/techniques/T1569/002/ |
| T1543.003 | Create or Modify System Process: Windows Service | https://attack.mitre.org/techniques/T1543/003/ |

#### Description

This pages holds various queries that can be used to investigate and/or threat hunt on Windows Services. You can start large and then narrow your searches by using more refined queries and/or queries that targets specific things.

- Query #1 - List all Windows Service install events, which in MDE, should be sourced mainly from Event ID 4697 (https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)
- Query #2 - List all processes that are launched as a Windows Service through services.exe
- Query #3 - List all instances where a svchost.exe process was not launched by services.exe. This should typically never happen ... but Microsoft being Microsoft: https://x.com/SecurityAura/status/1882420001099198907 . Therefore, some filtering needs to be added.
- Query #4 - List all instances where a svchost.exe process was launched without command line arguments (parameters). This should typically never happen but, see comment about Query #3.
- Query #5 - Threshold-based query that lists Windows Service install events, based on ServiceName, that are rare in the environment (read: not observed on many devices)
- Query #6 - List all instances of Windows Service install events or processes launched via services.exe where the binary of the associated service is located in a temp folder (System %TEMP% or user %TEMP%)

The queries listed here are meant to get you started in your capture of relevant events and drill down. Depending on the query, you can use "distinct" or "summarize count()" to get a better idea of how many events/results you're dealing with.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 6 queries

## Microsoft Defender XDR ##
### Query #1 - Defender for Endpoint (MDE) via DeviceEvents - ServiceInstalled Events ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
// If you want to filter out ephemeral services that are created on user logon/logout, uncomment the line below
//| where not (ServiceName matches regex "(?i)([A-Za-z]+)_[A-Fa-f0-9]+$")
// Editor's choice for first layer of summarization
//| summarize ["ServiceBinPaths"]=make_set(strcat(FolderPath,"\\",FileName)),
             ["ServiceBinPathCount"]=dcount(strcat(FolderPath,"\\",FileName))
             by ServiceName
```
### Query #2 - Defender for Endpoint (MDE) via DeviceProcessEvents - Process launched as Windows Service
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe"
```
### Query #3 - Defender for Endpoint (MDE) via DeviceProcessEvents - svchost.exe not launched by services.exe ###
```KQL
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where InitiatingProcessFileName != "services.exe"
// Editor's choice for first layer of filtering
//| summarize count() by InitiatingProcessFolderPath, InitiatingProcessCommandLine, FolderPath, ProcessCommandLine
```
### Query #4 - Defender for Endpoint (MDE) via DeviceProcessEvents - svchost.exe launched with no command line argument ###
```KQL
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where ProcessCommandLine in~ ("svchost.exe",'"svchost.exe"')
```
### Query #5 - Defender for Endpoint (MDE) via DeviceEvents - Rare Windows Service Install Across Devices Based on ServiceName ###
```
// Adjust the threshold accordingly
let DeviceThreshold = 5;
DeviceEvents
| where TimeGenerated > ago(90d)
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
// Here you want to filter out ephemeral services that are created on user logon/logout
| where not (ServiceName matches regex "(?i)([A-Za-z]+)_[A-Fa-f0-9]+$")
| summarize ["Devices"]=make_set(DeviceName),
            ["DeviceCount"]=dcount(DeviceName),
            ["ServiceBinPaths"]=make_set(strcat(FolderPath,"\\",FileName)),
            ["ServiceBinPathCount"]=dcount(strcat(FolderPath,"\\",FileName))
            by ServiceName
| where DeviceCount < DeviceThreshold
```
### Query #6 - Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceEvents - Windows Service Installed and/or Executed from a Temporary Folder ###
```
let WindowsServiceInstallTemp = (
    DeviceEvents
    | where TimeGenerated > ago(90d)
    | where ActionType == "ServiceInstalled"
    | extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
    | extend ServiceBinPath = strcat(FolderPath,"\\",FileName)
    | where ServiceBinPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?"
        or ServiceBinPath matches regex @"(?i):\\Windows\\Temp\\(.*)?"
);
let WindowsServiceExecuteTemp = (
    DeviceProcessEvents
    | where TimeGenerated > ago(90d)
    | where InitiatingProcessFileName =~ "services.exe"
    | where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?"
        or FolderPath matches regex @"(?i):\\Windows\\Temp\\(.*)?"
);
union WindowsServiceInstallTemp, WindowsServiceExecuteTemp
```
## Microsoft Defender Sentinel ##
### Query #1 - Defender for Endpoint (MDE) via DeviceEvents - ServiceInstalled Events ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
// If you want to filter out ephemeral services that are created on user logon/logout, uncomment the line below
//| where not (ServiceName matches regex "(?i)([A-Za-z]+)_[A-Fa-f0-9]+$")
// Editor's choice for first layer of summarization
//| summarize ["ServiceBinPaths"]=make_set(strcat(FolderPath,"\\",FileName)),
             ["ServiceBinPathCount"]=dcount(strcat(FolderPath,"\\",FileName))
             by ServiceName
```
### Query #2 - Defender for Endpoint (MDE) via DeviceProcessEvents - Process launched as Windows Service
```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe"
```
### Query #3 - Defender for Endpoint (MDE) via DeviceProcessEvents - svchost.exe not launched by services.exe ###
```KQL
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where InitiatingProcessFileName != "services.exe"
// Editor's choice for first layer of filtering
//| summarize count() by InitiatingProcessFolderPath, InitiatingProcessCommandLine, FolderPath, ProcessCommandLine
```
### Query #4 - Defender for Endpoint (MDE) via DeviceProcessEvents - svchost.exe launched with no command line argument ###
```KQL
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where ProcessCommandLine in~ ("svchost.exe",'"svchost.exe"')
```
### Query #5 - Defender for Endpoint (MDE) via DeviceEvents - Rare Windows Service Install Across Devices Based on ServiceName ###
```
// Adjust the threshold accordingly
let DeviceThreshold = 5;
DeviceEvents
| where TimeGenerated > ago(90d)
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
// Here you want to filter out ephemeral services that are created on user logon/logout
| where not (ServiceName matches regex "(?i)([A-Za-z]+)_[A-Fa-f0-9]+$")
| summarize ["Devices"]=make_set(DeviceName),
            ["DeviceCount"]=dcount(DeviceName),
            ["ServiceBinPaths"]=make_set(strcat(FolderPath,"\\",FileName)),
            ["ServiceBinPathCount"]=dcount(strcat(FolderPath,"\\",FileName))
            by ServiceName
| where DeviceCount < DeviceThreshold
```
### Query #6 - Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceEvents - Windows Service Installed and/or Executed from a Temporary Folder ###
```
let WindowsServiceInstallTemp = (
    DeviceEvents
    | where TimeGenerated > ago(90d)
    | where ActionType == "ServiceInstalled"
    | extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
    | extend ServiceBinPath = strcat(FolderPath,"\\",FileName)
    | where ServiceBinPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?"
        or ServiceBinPath matches regex @"(?i):\\Windows\\Temp\\(.*)?"
);
let WindowsServiceExecuteTemp = (
    DeviceProcessEvents
    | where TimeGenerated > ago(90d)
    | where InitiatingProcessFileName =~ "services.exe"
    | where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?"
        or FolderPath matches regex @"(?i):\\Windows\\Temp\\(.*)?"
);
union WindowsServiceInstallTemp, WindowsServiceExecuteTemp
```
