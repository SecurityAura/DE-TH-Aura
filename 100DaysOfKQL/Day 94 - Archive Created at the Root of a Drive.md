# *Archive Created at the Root of a Drive*

## Query Information

This query return events where an archive is created at the root of a drive.

##

#### Description

This query return events where an archive (ZIP, RAR or 7Z) is created at the root of a drive (C:\, D:\, E:\, etc.)

The logic behind that query is simple: a lot of threat actors, when going for the collection phase, will end up staging data at the root of a drive. Why? Because when they're on key servers such as File Servers, Backup Servers, etc. they may simply right-click on folders at the root and archive them using their preferred tool. Or even define the output path to be at the root of these drives when compressing files through the command line.

While this aligns with T1074 (Data Staged), this is more of a general observation as to where/how threat actors decide to stage their files for future the exfiltration phrase. If you're lucky enough that these archives still exists during an investigation ... you've just hit the jackpot.

Note: The false positives you may get the most are files on USB Flash Drives that gets observed by MDE. In terms of Threat Hunting, these should be more obvious to dismiss. RAR and or 7Z files, if WinRAR and/or 7-Zip aren't used in your environment can be suspicious from the get go.

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

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
// We're excluding the C:\ drive since our hypothesis is that the threat actor is compressing files from other drives
| where FolderPath matches regex @"(?i)[^c]:\\[^\\]+$"
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ ("zip","rar","7z")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
// We're excluding the C:\ drive since our hypothesis is that the threat actor is compressing files from other drives
| where FolderPath matches regex @"(?i)[^c]:\\[^\\]+$"
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ ("zip","rar","7z")
```
