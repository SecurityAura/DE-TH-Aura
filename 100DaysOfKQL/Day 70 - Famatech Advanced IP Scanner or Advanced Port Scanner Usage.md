# *Famatech Advanced IP Scanner or Advanced Port Scanner Usage*

## Query Information

| Date | Comments |
|---|---|
| 2025/03/12 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1046 | Network Service Discovery | https://attack.mitre.org/techniques/T1046/ |

#### Description

This query returns events where Famatech Advanced IP Scanner or Advanced Port Scanner is used.

Similar to SoftPerfect Network Scanner (netscan.exe), these two (2) tools needs no introduction and there's literally nothing to say about it other than, just make sure that if you have a hit for it, make sure that it's actually used legitimately.

Sadly, they seem to be more commonly used/leveraged by SysAdmins than netscan.exe.

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
### Microsoft Defender for Endpoint via DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents (union) ###
```KQL
union DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents
| where FileName has_any ("advanced_port_scanner","advanced_ip_scanner")
    or InitiatingProcessFileName has_any ("advanced_port_scanner","advanced_ip_scanner")
    or ProcessVersionInfoCompanyName has "Famatech"
    or ProcessVersionInfoProductName has_any ("Advanced Port Scanner","Advanced IP Scanner")
    or ProcessVersionInfoInternalFileName has_any ("Advanced Port Scanner","advanced_ip_scanner.exe","advanced_port_scanner.exe")
    or ProcessVersionInfoFileDescription has_any ("Advanced Port Scanner","Advanced IP Scanner")
    or InitiatingProcessVersionInfoCompanyName has "Famatech"
    or InitiatingProcessVersionInfoProductName has_any ("Advanced Port Scanner","Advanced IP Scanner")
    or InitiatingProcessVersionInfoFileDescription has_any ("Advanced Port Scanner","Advanced IP Scanner")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents (union) ###
```KQL
union DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents
| where FileName has_any ("advanced_port_scanner","advanced_ip_scanner")
    or InitiatingProcessFileName has_any ("advanced_port_scanner","advanced_ip_scanner")
    or ProcessVersionInfoCompanyName has "Famatech"
    or ProcessVersionInfoProductName has_any ("Advanced Port Scanner","Advanced IP Scanner")
    or ProcessVersionInfoInternalFileName has_any ("Advanced Port Scanner","advanced_ip_scanner.exe","advanced_port_scanner.exe")
    or ProcessVersionInfoFileDescription has_any ("Advanced Port Scanner","Advanced IP Scanner")
    or InitiatingProcessVersionInfoCompanyName has "Famatech"
    or InitiatingProcessVersionInfoProductName has_any ("Advanced Port Scanner","Advanced IP Scanner")
    or InitiatingProcessVersionInfoFileDescription has_any ("Advanced Port Scanner","Advanced IP Scanner")
```
