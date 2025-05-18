# *Virtual Drive Mounted From Archive*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/10 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.002 | User Execution: Malicious File | https://attack.mitre.org/techniques/T1204/002/ |

#### Description

This query returns events where a virtual drive file, hidden inside an archive (virtual drive smuggling?), would've been mounted by a user who double-clicked on it, within that archive.

When you double-click on file inside an archive without extracting it, may it be ZIP, 7z, RAR, etc. it'll be temporarily extracted in the user's %TEMP% folder and launched. The same goes for virtual drive. They'll be residing in the %TEMP% folder, underneat the folder of whatever application was used to go "inside" the archive and double-click on the virtual drive as long as it's mounted.

![image](https://github.com/user-attachments/assets/8368a363-4ab5-4aa7-9467-9a7395d60c02)

Therefore, we can look for file events where a file with a "virtual drive" (or image) extension such as VHD, VHDX, VMDK, ISO, etc. is created within an extracted archive folder in the user's %TEMP% folder.

PS: You may want to read this article from Palo Alto which references CVE-2023-36884 and what happened to the use of the "Temp1" folder in %TEMP%.

https://unit42.paloaltonetworks.com/new-cve-2023-36584-discovered-in-attack-chain-used-by-russian-apt/

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

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
let DiskImageFileExtensions = dynamic([
    "iso",
    "img",
    "vhd",
    "vhdx",
    "wim"
]);
DeviceFileEvents
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?"
| where FolderPath has_any ("7zo","Rar$",".zip","Temp1_")
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ (DiskImageFileExtensions)
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
let DiskImageFileExtensions = dynamic([
    "iso",
    "img",
    "vhd",
    "vhdx",
    "wim"
]);
DeviceFileEvents
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\AppData\\Local\\Temp\\(.*)?"
| where FolderPath has_any ("7zo","Rar$",".zip","Temp1_")
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ (DiskImageFileExtensions)
```
