# *Execution from a Low Prevalence, Non-Signed or Invalidly Signed Binary from C:\Windows*

## Query Information

This query returns events where low prevalence, non-signed or invalidly signed binary is executed from the C:\Windows folder.

##

#### Description

This query returns events where low prevalence, non-signed or invalidly signed binary is executed from the C:\Windows folder.

The reasoning behind this query is simple: catch unknown binary files that are executed remotely in a PsExec-like way on Windows. Since most of these, such as the ones launched by PsExec.exe -c, will end up being dropped and executed from the C:\Windows folder, which should only have known, trusted and signed binaries in it (I'll remove my rose colored-glasses after hitting Commit on this page), this query should highlight the outliers.

Obviously this query will not trigger on prevalent and signed files (e.g.: tools) that could be abused by threat actors.

These queries are only available in Defender XDR (Advanced Hunting) since they rely on FileProfile().

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
// Threshold-based rule, which mean that you should adjust this value to one that fits your environment and needs
let GlobalPrevalenceThreshold = 500;
DeviceProcessEvents
| where FolderPath matches regex @"(?i)C\:\\WINDOWS\\[^\\]+$"
| summarize ["Devices"]=make_set(DeviceName),
            ["DeviceCount"]=dcount(DeviceName)
            by FolderPath, SHA1
| invoke FileProfile("SHA1",1000)
| where GlobalPrevalence < GlobalPrevalenceThreshold
    or SignatureState in ("Unsigned", "SignedInvalid")
```
## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
// Threshold-based rule, which mean that you should adjust this value to one that fits your environment and needs
let GlobalPrevalenceThreshold = 500;
DeviceProcessEvents
| where FolderPath matches regex @"(?i)C\:\\WINDOWS\\[^\\]+$"
| summarize ["Devices"]=make_set(DeviceName),
            ["DeviceCount"]=dcount(DeviceName)
            by FolderPath, SHA1
| invoke FileProfile("SHA1",1000)
| where GlobalPrevalence < GlobalPrevalenceThreshold
    or SignatureState in ("Unsigned", "SignedInvalid")
```
