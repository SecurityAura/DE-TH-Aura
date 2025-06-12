# *Windows Service Environment Registry Value Modification*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/11 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1112 | Modify Registry | https://attack.mitre.org/techniques/T1112/ |

#### Description

This query looks for Registry events where the Environment Registry Value of a Windows Service Registry key is involved. Custom Environment variables can be set (or reassigned) this way which will be used by the service once it's executed. This could force it to load files (e.g.: DLLs) from an arbitrary, user-defined path in that Registry Value.

For the time being, I'm only tagging it as T1112, since we're looking at a Registry modification event. The end result could end up hitting more TTPs (such as DLL Hijack).

All the credits for this query idea goes to @Wietze (on Twitter/X) who shared this via his #HuntingTipOfTheDay.

https://x.com/Wietze/status/1932030614418424131

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### References

- https://www.wietzebeukema.nl/blog/save-the-environment-variables#implications-for-privilege-escalation-and-persistence

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Defender for Endpoint (MDE) via DeviceRegistryEvents ###
```KQL
DeviceRegistryEvents
| where RegistryKey matches regex @"(?i)HKEY_LOCAL_MACHINE\\SYSTEM\\(CurrentControlSet|ControlSet001)\\Services\\(.*?)"
| where RegistryValueName == "Environment"
```
## Microsoft Defender Sentinel ##
### Defender for Endpoint (MDE) via DeviceEvents ###
```KQL
DeviceRegistryEvents
| where RegistryKey matches regex @"(?i)HKEY_LOCAL_MACHINE\\SYSTEM\\(CurrentControlSet|ControlSet001)\\Services\\(.*?)"
| where RegistryValueName == "Environment"
```
