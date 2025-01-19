# *Unique DLL With Low Prevalence Loaded From Commonly Abused Folder*

## Query Information

This query returns events where unique DLLs with low prevalence that are loaded from commonly abused folders.

##

#### Description

This query returns events where unique DLLs, based on event count of their SHA1, with low prevalence, per FileProfile() are loaded from commonly abused folders. In this context, abused folders are basically folders where malware would either drop files directly and/or create subfolders and then drop their files. E.g.:

- C:\ProgramData\
- %AppData% (C:\Users\$USERNAME\AppData\Roaming\)
- %LocalAppData% (C:\Users\$USERNAME\AppData\Local\)

You'll often see this with malware that drops "legitimate" application and then use them to side-load a malicious DLL that was added in the package. For instance, a Lumma Stealer/Amadey Bot/Hijack Loader campaign at the end of Fall 2024 or even WikiLoader (see Reference(s) below).

There are separate queries for C:\ProgramData and %AppData%/%LocalAppData%. Reason being that, in the environment I tested this one, with a few thousand endpoints, it is very hard to get the initial filtering for unique DLLs under 1,000 in %AppData%/%LocalAppData%. And you want that filtering to be under 1,000 so it can be passed to FileProfile(). Additional filtering opportunities may exists. I simply excluded folders which are noisy and/or haven't seen being abused that way.

As for C:\ProgramData, I wasn't getting even near 1,000 results.

These queries are only available in Defender XDR (Advanced Hunting) since they rely on FileProfile().

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function
- https://cyble.com/blog/threat-actor-targets-manufacturing-industry-with-malware/
- https://asec.ahnlab.com/en/64106/

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 2 queries

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceImageLoadEvents (C:\ProgramData) ###
```KQL
let LowPrevDLLs = (DeviceImageLoadEvents
// We're only looking for DLLs loaded from these folders, in a context where the EXE that loads them would be in the same folder
| where InitiatingProcessFolderPath matches regex @"(?i)C\:\\ProgramData\\(.*)?"
| where FolderPath matches regex @"(?i)C\:\\ProgramData\\(.*)?"
| where FileName !endswith ".exe"
| summarize count() by SHA1
| where count_ == 1
| invoke FileProfile("SHA1",1000)
// Adjust the GlobalPrevalence filter as needed
| where GlobalPrevalence < 500
| distinct SHA1);
DeviceImageLoadEvents
| where InitiatingProcessFolderPath matches regex @"(?i)C\:\\ProgramData\\(.*)?"
| where FolderPath matches regex @"(?i)C\:\\ProgramData\\(.*)?"
| join kind=inner LowPrevDLLs on SHA1
```
## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceImageLoadEvents (%AppData%\%LocalAppData%) ###
```KQL
let LowPrevDLLs = (DeviceImageLoadEvents
// We're only looking for DLLs loaded from these folders, in a context where the EXE that loads them would be in the same folder
| where InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\(.*)?"
| where not (InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?")
| where not (InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\Apps\\(.*)?")
| where not (InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\Programs\\(.*)?")
| where FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\(.*)?"
| where FileName !endswith ".exe"
| summarize count() by SHA1
| where count_ == 1
| invoke FileProfile("SHA1",1000)
// Adjust the GlobalPrevalence filter as needed
| where GlobalPrevalence < 500
| distinct SHA1);
DeviceImageLoadEvents
| where InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\(.*)?"
| where not (InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?")
| where not (InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\Programs\\(.*)?")
| where FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\(.*)?"
| join kind=inner LowPrevDLLs on SHA1
```
