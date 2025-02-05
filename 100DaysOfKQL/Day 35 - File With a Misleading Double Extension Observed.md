# *File With a Misleading Double Extension Observed*

## Query Information

These queries returns events where a file with a misleading double extension is observed on a system.

##

#### Description

These queries returns events where a file with a misleading double extension (e.g.: masquerading as an Office or PDF file) is observed on a system.

The double file extension trick seems to have been making a comeback lately (at the very least, .pdf.lnk) with malware such as DarkGate, Lumma Stealer, Amadey Bot, HijackLoader (the last 3 being delivered in the same campaign). It is therefore interesting to see if any of these files would've been created at some point in locations where user are likely to execute these once delivered via a certain method (Web, Email, etc.).

False positives here may usually include shortcut files that are created from an actual file in File Explorer. Depending on your system language, you can usually filter out files with specific strings:

- Nouveau raccourci (in French)
- New shortcut (in English)

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://cyble.com/blog/threat-actor-targets-manufacturing-industry-with-malware/
- https://www.truesec.com/hub/blog/darkgate-loader-delivered-via-teams

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
// You can add more extensions as needed
let FileExtensions = dynamic([
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "pdf",
    "zip",
    "rar",
    "7z",
    "rtf"
]);
DeviceFileEvents
| extend FileExtension = tostring(strcat((split(FileName,".")[-2]),".",strcat(split(FileName,".")[-1])))
| where FileExtension has_any (FileExtensions)
| where FileExtension endswith "lnk"
| where FolderPath matches regex @'(?i)\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?'
    or FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
    or FolderPath matches regex @"(?i)\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\[^\\]+\\(.*)?"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
// You can add more extensions as needed
let FileExtensions = dynamic([
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "pdf",
    "zip",
    "rar",
    "7z",
    "rtf"
]);
DeviceFileEvents
| extend FileExtension = tostring(strcat((split(FileName,".")[-2]),".",strcat(split(FileName,".")[-1])))
| where FileExtension has_any (FileExtensions)
| where FileExtension endswith "lnk"
| where FolderPath matches regex @'(?i)\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?'
    or FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
    or FolderPath matches regex @"(?i)\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\[^\\]+\\(.*)?"
```
