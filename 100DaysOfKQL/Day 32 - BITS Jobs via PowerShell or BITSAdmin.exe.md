# *BITS Jobs via PowerShell or BITSAdmin.exe*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/01 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1197 | BITS Jobs | https://attack.mitre.org/techniques/T1197/ |

#### Description

These queries returns events where BITS Jobs are observed through PowerShell (Start-BitsTransfer) or bitsadmin.exe.

BITS remains a popular and easy way for threat actors to perform Ingress Tool Transfer (T1105). BITS Jobs can be created through PowerShell, using the Start-BitsTransfer cmdlet (there are other BITS-related cmdlets) or the now deprecated bitsadmin.exe utility.

From a detection standpoint, triggering on bitsadmin.exe should make a pretty good use case, since it's deprecated and not commonly used anymore (if at all). The only instances of it I've seen used in the last years were, well you guessed it: threat actors or malware.

There's also a dedicated Event Log, Microsoft-Windows-Bits-Client/Operational, where events related to BITS are logged. Amongst them is Event ID 16403, which contains:

- User associated with the BITS Job
- BITS Job name
- BITS Job remote name (download source)
- BITS Job local name (saved file location)

Which can be used for hunting. You can grab all these events in Microsoft Sentinel and from there, do a distinct on either the RemoteName or LocalName field to hunt for suspicious URLs, domains, file locations, etc.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://www.logpoint.com/en/blog/emerging-threats/hiding-in-plain-sight-the-subtle-art-of-loki-malwares-obfuscation/
- https://isc.sans.edu/diary/23281
- https://redcanary.com/blog/threat-detection/bitsadmin/
- https://cloud.google.com/blog/topics/threat-intelligence/attacker-use-of-windows-background-intelligent-transfer-service/

### Queries Overview ###

- Defender for Endpoint (MDE) - 2 queries
- Microsoft Sentinel (SecurityEvents) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "Start-BitsTransfer"
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
  or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Start-BitsTransfer")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "Start-BitsTransfer"
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
  or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Start-BitsTransfer")
```
### SecurityEvents ###
```KQL
Event
| where EventLog == "Microsoft-Windows-Bits-Client/Operational"
| where EventID == "16403"
| extend ParsedXML = parse_xml(EventData)
| extend RemoteName = ParsedXML.DataItem.EventData.Data[5]["#text"]
| extend LocalName = ParsedXML.DataItem.EventData.Data[6]["#text"]
```
