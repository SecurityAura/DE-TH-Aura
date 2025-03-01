# *DeviceNetworkEvents From FileZilla with Enriched IP Information*

## Query Information

This query returns events from network connections by FileZilla with enriched IP information.

##

#### Description

This query returns events from network connections (DeviceNetworkEvents) by FileZilla with enriched IP (RemoteIP) information, such as its geolocation and ASN. The ASN enrichment is done through GypTheCat[.]com awesome Kusto ASN Table. Once again, thank you to Matt Zorich (@reprise99) for showing me that site and resource!

https://firewalliplists.gypthecat.com/kusto-tables/kusto-asn-table/

The geolocation information is provided by Microsoft Sentinel built-in geo_info_from_ip_address() function.

This query is more suited for hunting purposes, unless you want to combine it with an IP and/or domain whitelist (through a Watchlist in Microsoft Sentinel for instance) if you know exactly where your users (or servers) should be connecting in outbound on ports such as 21 or 22 using FileZilla. Though if you knew about it, you would simply allowlist these connections in your firewall and block the rest amirite?

This being said, when it comes to data exfil, "simple is always best" and FileZilla, like WinSCP (tomorrow's spoiler maybe?), still remain a threat actor's favorite when it comes to exfiltrating data. Therefore, looking into which RemoteIPs or RemoteURLs FileZilla connects to, where the process is being launched from, was its filename changed (not FileZilla.exe, etc.) can help uncover non-legitimate use of FileZilla.

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
let CIDRASN = (
    externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string, CIDRSource:string)
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
    with (ignoreFirstRecord=true)
);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "filezilla.exe"
    or InitiatingProcessVersionInfoCompanyName has "FileZilla"
    or InitiatingProcessVersionInfoFileDescription has "FileZilla"
    or InitiatingProcessVersionInfoInternalFileName has "FileZilla"
    or InitiatingProcessVersionInfoOriginalFileName has "FileZilla"
    or InitiatingProcessVersionInfoProductName has "FileZilla"
| where RemoteIPType == "Public"
| where RemoteUrl !endswith ".filezilla-project.org"
| extend RemoteIPGeoLoc = geo_info_from_ip_address(RemoteIP)
| evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR, return_unmatched=true)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let CIDRASN = (
    externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string, CIDRSource:string)
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
    with (ignoreFirstRecord=true)
);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "filezilla.exe"
    or InitiatingProcessVersionInfoCompanyName has "FileZilla"
    or InitiatingProcessVersionInfoFileDescription has "FileZilla"
    or InitiatingProcessVersionInfoInternalFileName has "FileZilla"
    or InitiatingProcessVersionInfoOriginalFileName has "FileZilla"
    or InitiatingProcessVersionInfoProductName has "FileZilla"
| where RemoteIPType == "Public"
| where RemoteUrl !endswith ".filezilla-project.org"
| extend RemoteIPGeoLoc = geo_info_from_ip_address(RemoteIP)
| evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR, return_unmatched=true)
```
