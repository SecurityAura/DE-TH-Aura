# *PowerShell Invoke-WebRequest, IWR or Net.WebClient*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/15 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1105 | Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ |

#### Description

This query return events where the PowerShell Invoke-WebRequest/IWR (shortened version) cmdlet or the WebClient class was used. Useful for Ingress Tool Transfer (T1105) but also for data exfiltration if you want to send data out (e.g.: Registry Hive dumps, LSASS dump, etc.).

Often used by malware and threat actor alike (even APTs, see below). The kind of query that you want to run, look at the various unique iterations of the command (use distinct) and just see if you can spot anything suspicious/malicious.

Depending on their use in an environment, can act as a detection and/or can be fine-tuned to become one if more filters are added: execution context, destination IPs/domains, etc.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://www.huntress.com/blog/the-hunt-for-redcurl-2
- https://azeria-labs.com/data-exfiltration/

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 2 queries

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where InitiatingProcessCommandLine has_any ("Invoke-WebRequest", "IWR", "Net.WebClient")
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Invoke-WebRequest", "IWR", "Net.WebClient")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where InitiatingProcessCommandLine has_any ("Invoke-WebRequest", "IWR", "Net.WebClient")
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Invoke-WebRequest", "IWR", "Net.WebClient")
```
