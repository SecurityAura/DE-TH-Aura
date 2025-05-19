# *Network Connection from MSBuild.exe with ASN Enrichment*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/04/02 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1127.001 | Trusted Developer Utilities Proxy Execution: MSBuild | https://attack.mitre.org/techniques/T1127/001/ |

#### Description

This query returns events a network connection from MSBuild.exe to a public remote IP is observed and enrich the ASN information on the IP (RemoteIP) involved.

MSBuild.exe is a popular process in which malware choose to inject themselves and/or threat actors can use to load on a system a payload that is fetched remotely. This will result in network connection from the MSBuild.exe process and with a little bit of filtering and enrichment, suspicious and/or downright malicious instances of it can be spotted.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://www.malwarebytes.com/blog/news/2025/02/sectoprat-bundled-in-chrome-installer-distributed-via-google-ads
- https://www.threatdown.com/blog/bing-ad-for-nordvpn-leads-to-sectoprat/
- https://lolbas-project.github.io/lolbas/Binaries/Msbuild/

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
let MsBuildNetconnIpLookupEvents = (DeviceNetworkEvents
| where InitiatingProcessFileName =~ "msbuild.exe"
| where not (ipv4_is_private( RemoteIP))
| distinct RemoteIP
| evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR, return_unmatched=true));
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "msbuild.exe"
| where not (ipv4_is_private( RemoteIP))
| join MsBuildNetconnIpLookupEvents on RemoteIP
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let CIDRASN = (
    externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string, CIDRSource:string)
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
    with (ignoreFirstRecord=true)
);
let MsBuildNetconnIpLookupEvents = (DeviceNetworkEvents
| where InitiatingProcessFileName =~ "msbuild.exe"
| where not (ipv4_is_private( RemoteIP))
| distinct RemoteIP
| evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR, return_unmatched=true));
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "msbuild.exe"
| where not (ipv4_is_private( RemoteIP))
| join MsBuildNetconnIpLookupEvents on RemoteIP
```
