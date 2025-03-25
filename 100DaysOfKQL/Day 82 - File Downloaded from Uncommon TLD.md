# *File Downloaded from Uncommon TLD*

## Query Information

This query returns events where a file was most likely downloaded from a site/domain with an uncommon TLD.

##

#### Description

DISCLAIMER - I have to post this query quickly today. I'll comeback to it and update it with more information later on.

This query returns events where a file was most likely downloaded from a site/domain with an uncommon TLD.

Exploratory query that you can use to get events where an executable or archive, based on a dynamic variable, was most likely downloaded (in a user's Downloads folder) from a site/domain with an uncommon TLD (defined in a regex). You can adjust the file extensions you want to target and also which TLDs you want to define as "not" uncommon (e.g.: COM, NET, ORG, etc.)

A nice, little, fun query to explore a bit where your users are downloading files from.

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
// Add or remove extensions as needed
let TargetedExtensions = dynamic([
    "exe",
    "dll",
    "ps1",
    "cmd",
    "bat",
    "zip"
]);
DeviceFileEvents
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ (TargetedExtensions)
| where isnotempty( FileOriginUrl)
| where not (FileOriginUrl has_any ("file:///", "about:internet"))
| extend RootDomain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,FileOriginUrl))
| extend DomainTLD = tostring(split(RootDomain,".")[-1])
// Add or remove TLDs as needed
| where not (DomainTLD matches regex "(ca|com|net|org)")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
// Add or remove extensions as needed
let TargetedExtensions = dynamic([
    "exe",
    "dll",
    "ps1",
    "cmd",
    "bat",
    "zip"
]);
DeviceFileEvents
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ (TargetedExtensions)
| where isnotempty( FileOriginUrl)
| where not (FileOriginUrl has_any ("file:///", "about:internet"))
| extend RootDomain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,FileOriginUrl))
// Add or remove TLDs as needed
| extend DomainTLD = tostring(split(RootDomain,".")[-1])
| where not (DomainTLD matches regex "(ca|com|net|org)")
```
