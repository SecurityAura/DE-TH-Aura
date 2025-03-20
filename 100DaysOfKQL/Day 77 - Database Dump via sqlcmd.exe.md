# *Database Dump via sqlcmd.exe*

## Query Information

This query returns events where sqlcmd.exe is used to dump the content of a database.

##

#### Description

This query returns events where sqlcmd.exe is used to dump the content of a database (e.g.: tables) to files on disk.

Threat Actors can use sqlcmd.exe to query/select all events in specific SQL Server tables and redirect the output to a file on disk. They can automate that process by querying the SQL Server for all databases, list the schemas and tables for the various databases and from there, dump all tables one by one.

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
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "sqlcmd.exe"
| where ProcessCommandLine has_all (" -Q ", " -o ")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "sqlcmd.exe"
| where ProcessCommandLine has_all (" -Q ", " -o ")
```
