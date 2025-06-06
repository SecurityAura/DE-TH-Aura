# *Executable File Fetched via WebDAV From External Host*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/06 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |
| T1204 | User Execution | https://attack.mitre.org/techniques/T1204/ |

#### Description

This query looks for WebDAV GET or PROPFIND requests to an external host targeting file with a known executable extension/format that are leveraged by threat actors or malware. This query will only hit on non-SSL WebDAV requests since it leverages the HttpConnectionInspected ActionType. Which means, it will not work against these WebDAV-campaigns that are hosted on trycloudflare[.]com. Not all WebDAV servers used to host malicious payloads have SSL enabled however.

Additional file extensions can be added as needed to the regex at the end.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://blog.sekoia.io/webdav-as-a-service-uncovering-the-infrastructure-behind-emmenhtal-loader-distribution/
- https://cyble.com/blog/strela-stealer-targets-europe-stealthily-via-webdav/
- https://www.proofpoint.com/au/blog/threat-insight/malware-must-not-be-named-suspected-espionage-campaign-delivers-voldemort
- https://micahbabinski.medium.com/search-ms-webdav-and-chill-99c5b23ac462

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Defender for Endpoint (MDE) via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where ActionType == "HttpConnectionInspected"
| where RemoteIPType == "Public"
| extend UserAgent = tostring(parse_json(AdditionalFields).user_agent)
| extend URI = tostring(parse_json(AdditionalFields).uri)
| extend Method = tostring(parse_json(AdditionalFields).method)
| where UserAgent has "WebDAV"
| where Method in ("GET","PROPFIND")
| where URI matches regex @"(?i)\.(exe|bat|cmd|com|sys|ps1|dll|lnk|vb|vbs|vbe|js|jse|ws|wse|wsf|hta)$"
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where ActionType == "HttpConnectionInspected"
| where RemoteIPType == "Public"
| extend UserAgent = tostring(parse_json(AdditionalFields).user_agent)
| extend URI = tostring(parse_json(AdditionalFields).uri)
| extend Method = tostring(parse_json(AdditionalFields).method)
| where UserAgent has "WebDAV"
| where Method in ("GET","PROPFIND")
| where URI matches regex @"(?i)\.(exe|bat|cmd|com|sys|ps1|dll|lnk|vb|vbs|vbe|js|jse|ws|wse|wsf|hta)$"
```
