# *Potential secretsdump remoteSSMethod - SAM, SECURITY and SYSTEM Accessed Remotely*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/07/10 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1047 | Windows Management Instrumentation | https://attack.mitre.org/techniques/T1047/ |
| T1003 | OS Credential Dumping | https://attack.mitre.org/techniques/T1003/ |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |

#### Description

This query looks for Event ID 5145 where one of the accessed file is the SAM, SECURITY or SYSTEM Registry Hive. Which means, Audit Detailed File Share must be enabled on the target system for these events to be logged.

This idea has been inspired by Stephen Berger (@malmoeb on Twitter/X) tweet, since it was related to an article (referenced below) from ITRES that I had read just a few days prior.

https://x.com/malmoeb/status/1943310097905533302

Note that I may add other queries for this as I believe that there may be more than one detection opportunity here, other than the ones listed by ITRES.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### References ####

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145
- https://labs.itresit.es/2025/06/11/remote-windows-credential-dump-with-shadow-snapshots-exploitation-and-detection/

### Queries Overview ###

- Microsoft Sentinel (SecurityEvent) - 1 query

## Microsoft Sentinel ##
### SecurityEvent ###
```KQL
SecurityEvent
| where EventID == "5145"
| where RelativeTargetName in~ (@"System32\config\SECURITY",@"System32\config\SYSTEM",@"System32\config\SAM")
```
