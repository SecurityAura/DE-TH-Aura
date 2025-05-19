# *Sysinternals Usage*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/07 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events where a Sysinternal utility/tool is used.

PS: For more immediate context, Sysinternals tools can be (ab)used by threat actors in intrusion: PsExec to execute processes/commands, AdExplorer to "dump" the AD information, ProcDump to dump process memory, etc. Knowing which Sysinternals tools are used legitimately within your environment and how can help you spot the odd one out.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where ProcessVersionInfoCompanyName has "Sysinternals"
    or ProcessVersionInfoProductName has "Sysinternals"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where ProcessVersionInfoCompanyName has "Sysinternals"
    or ProcessVersionInfoProductName has "Sysinternals"
```
