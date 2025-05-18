# *nltest.exe Execution*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/11 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1482 | Domain Trust Discovery | https://attack.mitre.org/techniques/T1482 |
| T1018 | Remote System Discovery | https://attack.mitre.org/techniques/T1018 |
| T1016 | System Network Configuration Discovery | https://attack.mitre.org/techniques/T1016 |

#### Description

This query returns events where nltest.exe was executed.

That's it, that's the description. At this point, it should be well-known to any instance of nltest.exe should be investigated because:

- It really is not run that often in the day-to-day
- Once again, it really is not run that often in the day-to-day
- It is quite easy to find out if its execution was done legitimately (benign, expected behavior or not)

If you get a hit on this, it only takes a few seconds to look at all the DeviceProcessEvents surrounding that event to see if it's coupled with other discovery related commands, come from an account that should not be running that command, was executed at odd hours, etc.

In terms of "low-hanging fruit" indicators of an intrusion (e.g.: ransomware attack), this is easily in the Top 5.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://attack.mitre.org/software/S0359/
- https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/
- https://www.threatdown.com/blog/5-early-signs-of-a-ransomware-attack-based-on-real-examples/
- https://news.sophos.com/en-us/2025/01/21/sophos-mdr-tracks-two-ransomware-campaigns-using-email-bombing-microsoft-teams-vishing/
- There are just SO many

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "nltest.exe"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "nltest.exe"
```
