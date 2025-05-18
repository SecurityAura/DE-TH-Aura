# *Network Connection From Python-related Process*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/27 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.006 | Command and Scripting Interpreter: Python | https://attack.mitre.org/techniques/T1059/006/ |

#### Description

This query returns events when a network event (e.g.: outbound connection) involving a process associated with Python (from a known list of processes on Windows) is observed.

This was observed recently in an incident Huntress responded to involving RedCurl (AKA RedWolf), a cyber-espionnage APT:

https://www.huntress.com/blog/the-hunt-for-redcurl-2

And I can also say that I've personally observed the same in a RedCurl incident from 2023/2024. Depending on how Python is leveraged in your environment, this would be more of a threat hunting query rather than a detection. 

In the events that Huntress (and myself) observed, an IP address was passed with the rpivot client script. Which means, you can also adjust the query to look only for events where an IP address (per a regex) is present in the command line.

That kind of technique is also well alive in malware distributed through SEO poisoning and the likes. See the Reference(s) section below.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://www.securonix.com/blog/seolurker-attack-campaign-uses-seo-poisoning-fake-google-ads-to-install-malware/
- https://www.esentire.com/blog/batloader-continues-to-abuse-google-search-ads-to-deliver-vidar-stealer-and-ursnif
- https://www.guidepointsecurity.com/blog/ransomhub-affiliate-leverage-python-based-backdoor/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let PythonProcesses = dynamic([
  "python.exe",
  "pythonw.exe",
  "py.exe",
  "pyw.exe"
]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (PythonProcesses)
| where RemoteIPType == "Public"
// You can uncomment the line below if you're looking for processes where an IP address is specified in the command line
//| where InitiatingProcessCommandLine matches regex @"(?i)(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let PythonProcesses = dynamic([
  "python.exe",
  "pythonw.exe",
  "py.exe",
  "pyw.exe"
]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (PythonProcesses)
| where RemoteIPType == "Public"
// You can uncomment the line below if you're looking for processes where an IP address is specified in the command line
//| where InitiatingProcessCommandLine matches regex @"(?i)(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
```
