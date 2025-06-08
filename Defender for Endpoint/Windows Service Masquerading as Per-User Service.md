# *Windows Service Masquerading as Per-User Service*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/08 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1569.002 | System Services: Service Execution | https://attack.mitre.org/techniques/T1569/002/ |
| T1543.003 | Create or Modify System Process: Windows Service | https://attack.mitre.org/techniques/T1543/003/ |
| T1036.004 | Masquerading: Masquerade Task or Service | https://attack.mitre.org/techniques/T1036/004/ |

#### Description

This query return ServiceInstalled for services whose name matches the naming convention used by per-user services in Windows 10+, but for which the associated service binary is not expected.

Per-user services on Windows 10+ will always be associated with C:\Windows\System32\svchost.exe, except for the CredentialEnrollmentManagerUserSvc which is associated with C:\Windows\System32\CredentialEnrollmentManager.exe. Since these service names can be regex'd and their associated binary is known, we can easily craft a query that looks for services masquerading as these, which points to other binaries.

False positives are possible on certain services from what I've seen, such as Realtek driver:

- ServiceName = RtkUsbAD_2370 | ServiceBinPath = \SystemRoot\System32\DriverStore\FileRepository\[OMITTED]\RtUsbA64.sys

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### References

- https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Defender for Endpoint (MDE) via DeviceEvents - ServiceInstalled Events ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| where ServiceName matches regex "(?i)^[A-Za-z]+_[A-Fa-f0-9]+$"
| extend ServiceBinPath = strcat(FolderPath,"\\",FileName)
| where ServiceBinPath !in~ ("C:\\WINDOWS\\System32\\svchost.exe", "C:\\Windows\\System32\\CredentialEnrollmentManager.exe")
```
## Microsoft Defender Sentinel ##
### Defender for Endpoint (MDE) via DeviceEvents - ServiceInstalled Events ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| where ServiceName matches regex "(?i)^[A-Za-z]+_[A-Fa-f0-9]+$"
| extend ServiceBinPath = strcat(FolderPath,"\\",FileName)
| where ServiceBinPath !in~ ("C:\\WINDOWS\\System32\\svchost.exe", "C:\\Windows\\System32\\CredentialEnrollmentManager.exe")
```
