# *DeviceNetworkEvents From Windows Processes and Domains by TLD (Summarized)*

## Query Information

#### Changelog
| Date | Comments |
|---|---|
| 2025/01/07 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

A very simple query I came with today as I was looking for a way to cast a "wide" net on which TLDs have been observed for DeviceNetworkEvents from processes coming in the C:\Windows folder.

Think of it as a very "large" query that, if you review the results, could show processes in C:\Windows which may have been the target of process injection and are now beaconing to C2s. Assuming these C2s are under an uncommon and/or known abused TLD, think: .top, .cc, .shop, etc.

It may also allow you to identify weird, but legitimate, applications (think WTFBins, but on a network level maybe). At the very least, this is what happened today for me!

Obviously, you can edit that query quite easily to target another folder (or even other folders). The summarization used is one that fits my needs, but you may adjust it depending on yours.

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
### Defender for Endpoint (MDE) via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where RemoteIPType == "Public"
// You can change the path as needed
| where InitiatingProcessFolderPath startswith @"C:\Windows\"
| extend RootDomain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,RemoteUrl))
| extend DomainTLD = tostring(split(RootDomain,".")[-1])
| summarize count(), 
            ["RootDomains"] = make_set(RootDomain),
            ["Processes"]= make_set(InitiatingProcessFolderPath),
            ["ProcessesCount"] = dcount(InitiatingProcessFolderPath)
            by DomainTLD
// If you want to filter out very popular TLDs (e.g.: com, net, org, etc.) simply run the query once, find out where your "count" limit would be then uncomment and adjust the value
//| where count_ < 2000
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where RemoteIPType == "Public"
// You can change the path as needed
| where InitiatingProcessFolderPath startswith @"C:\Windows\"
| extend RootDomain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,RemoteUrl))
| extend DomainTLD = tostring(split(RootDomain,".")[-1])
| summarize count(), 
            ["RootDomains"] = make_set(RootDomain),
            ["Processes"]= make_set(InitiatingProcessFolderPath),
            ["ProcessesCount"] = dcount(InitiatingProcessFolderPath)
            by DomainTLD
// If you want to filter out very popular TLDs (e.g.: com, net, org, etc.) simply run the query once, find out where your "count" limit would be then uncomment and adjust the value
//| where count_ < 2000
```
