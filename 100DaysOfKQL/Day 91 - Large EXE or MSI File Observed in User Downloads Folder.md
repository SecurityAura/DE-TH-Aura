# *Large EXE or MSI File Observed in User Downloads Folder*

## Query Information

This query returns events when a large EXE or MSI file is observed in a user's Downloads folder.

##

#### Description

This query returns events when a large (over 300 MB) EXE or MSI file is observed in a user's Downloads folder.

Defender for Endpoint (MDE) has a known limitation with large files (at least 300+ MB): hashes for it aren't computed/present in the various tables (DeviceFileEvents, DeviceProcessEvents, etc.). Therefore, it is hard to do anything with them at a hash level (e.g.: look up their DeviceFileCertificateInfo, FileProfile(), etc.).

Using large files in initial access isn't new, but it sure is the favorite technique used by some malware (hello SolarMarker!). Most of them are actually inflated/bloated using multiple techniques. You can "debloat" them using a tool of the same name by @Squiblydoo.

https://github.com/Squiblydoo/debloat

Some online services, such as MalwareBazaar, also support debloating inflated binaries.

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
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @'(?i)\\Users\\[^\\]+\\Downloads\\(.*)?'
| where isempty( SHA1)
// 300 MB
| where FileSize > 300000000
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ ("exe","msi")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @'(?i)\\Users\\[^\\]+\\Downloads\\(.*)?'
| where isempty( SHA1)
// 300 MB
| where FileSize > 300000000
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ ("exe","msi")
```
