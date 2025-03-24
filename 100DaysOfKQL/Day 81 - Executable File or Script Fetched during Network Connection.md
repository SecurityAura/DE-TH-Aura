# *Executable File or Script Fetched during Network Connection*

## Query Information

This query returns events where a file or a script was fetched (or attempted to) during a network connection.

##

#### Description

DISCLAIMER - I have to post this query quickly today. I'll comeback to it and update it with more information later on.

This query returns events where a file or a script was fetched (or attempted to) during a network connection.

Exploratory query that you can use to get events where an executable file or script (e.g.: EXE, DLL, PS1, CMD, BAT, etc.) was fetched (read: GET, downloaded, etc.) during a network connection by a system. Technically, only files fetched through HTTP should show up in the results.

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
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where RemoteUrl matches regex @"(?i)\.(exe|msi|dll|ps1|cmd|bat|sys)$"
| where RemoteUrl !has ".download.windowsupdate.com/"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where RemoteUrl matches regex @"(?i)\.(exe|msi|dll|ps1|cmd|bat|sys)$"
| where RemoteUrl !has ".download.windowsupdate.com/"
```
