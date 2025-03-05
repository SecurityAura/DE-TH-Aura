# *File Added to Startup Folder*

## Query Information

This query returns events where a file was added to Windows' Startup folder.

##

#### Description

This query returns events where a file was added to Windows' Startup folder, may it be for all users (C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup) or a specific user (%AppData%\Microsoft\Windows\Start Menu\Programs\Startup).

A few years back, adding a file in the Startup folder to kick-off a malware and/or process used to be all the rage with commodity malware. It seems to be less common these days, but it can still be seen in certain malware families.

Depending on the environment, it should be pretty quick to see whether a file that gets created in a Startup folder is legitimate or not. Even more depending on the extension it has. For instance, script files such as PS1 and CMD/BAT are suspicious, but so are JS, JSE, WS, WSE, etc.

Nowaday, with LNKs being abused for all kind of things, including being dropped in Startup folders, they also should not be overlooked.

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
| extend FileExtension = tostring(split(FileName,".")[-1])
| where FolderPath matches regex @'(?i)\\Microsoft\\Windows\\Start\ Menu\\Programs\\Startup\\(.*)?'
// We "normalize" the FolderPath if it's a single user one (C:\Users\USERNAME\AppData\[...]) to assist in our summarization (clustering)
| extend NormalizedFolderPath = replace(@'(?i)C\:\\Users\\[^\\]+\\',@"C:\Users\USERNAME\",FolderPath)
| summarize ["Devices"]=make_set(DeviceName),
            ["Number of Devices"]=dcount(DeviceName)
            by NormalizedFolderPath
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| extend FileExtension = tostring(split(FileName,".")[-1])
| where FolderPath matches regex @'(?i)\\Microsoft\\Windows\\Start\ Menu\\Programs\\Startup\\(.*)?'
// We "normalize" the FolderPath if it's a single user one (C:\Users\USERNAME\AppData\[...]) to assist in our summarization (clustering)
| extend NormalizedFolderPath = replace(@'(?i)C\:\\Users\\[^\\]+\\',@"C:\Users\USERNAME\",FolderPath)
| summarize ["Devices"]=make_set(DeviceName),
            ["Number of Devices"]=dcount(DeviceName)
            by NormalizedFolderPath
```
