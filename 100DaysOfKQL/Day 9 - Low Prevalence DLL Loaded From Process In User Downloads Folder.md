# *Low Prevalence DLL Loaded From Process In User Downloads Folder*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/09 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.002 | User Execution: Malicious File | https://attack.mitre.org/techniques/T1204/002/ |
| T1574.001 | Hijack Execution Flow: DLL | https://attack.mitre.org/techniques/T1574/001/ |

#### Description

This query returns events where a DLL with a low prevalence, per Defender XDR FileProfile() was loaded from a user's Downloads folder, by a process in the same folder (or subfolder). This is a detection or hunting query aimed at detecting initial access from malware that uses DLL sideloading for execution.

The chain of events here is basically a user would go on the Internet, download an archive (e.g.: ZIP) that has multiple files in it: legit EXE, MSI, etc., a few legit DLLs and a malicious one. He extracts the content of the archive where it is right now, often in the Downloads folder, where it was downloaded and then proceeds to execute the EXE, MSI, etc.

This is what you would see in Nitrogen-related infection. The downside of this query, obviously, is that it only works in Advanced Hunting (Defender XDR console) since it makes use of FileProfile() (https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function)

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://www.threatdown.com/blog/nitrogen-shelling-malware-from-hacked-sites/
- https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/
- https://news.sophos.com/en-us/2023/07/26/into-the-tank-with-nitrogen/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query


## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceImageLoadEvents ###
```KQL
let LoadedDLLs = (
    DeviceImageLoadEvents
    | where InitiatingProcessFolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
    | where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
    | where FileName endswith ".dll"
    | distinct SHA1
    // The FileProfile() has a limit of 1000 lookup/query.
    | invoke FileProfile("SHA1",1000)
);
DeviceImageLoadEvents
| where InitiatingProcessFolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
| where FileName endswith ".dll"
| join kind=inner LoadedDLLs on SHA1
// You can add a filter on the GlobalPrevalence column if you wish to reduce the number of results, though I suggest to simply order them from lowest to highest and look for the ones with the lowest prevalence
//| where GlobalPrevalence < 500
//| order by GlobalPrevalence asc
```
