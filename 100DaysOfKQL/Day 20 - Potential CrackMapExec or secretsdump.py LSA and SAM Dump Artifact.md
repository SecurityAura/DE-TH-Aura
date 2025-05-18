# *Potential CrackMapExec or secretsdump.py LSA and SAM Dump Artifact*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/20 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003.004 | OS Credential Dumping: LSA Secrets | https://attack.mitre.org/techniques/T1003/004/ |

#### Description

This query return events which may indicates that secretsdump.py, to dump LSA & SAM, was used against a queried system.

This is actually something I randomly found/noticed while testing secretsdump.py a while back. Even turned it into a Sigma rule (my first and only one to this day):

https://github.com/SigmaHQ/sigma/blob/fb27bee6d8d6eaac4b4d2875ae81b643553fc413/rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.yml#L8

Basically, back then, when used against a remote endpoint, CrackMapExec --lsa and secretsdump.py would end up creating a very specific temporary file on the remote system, following this regex pattern:

- C\:\\Windows\\System32\\[a-zA-Z0-9]{8}.tmp

This file would be created by the svchost.exe process for the RemoteRegistry service. A few months later, maybe even a year or so later, when I tested it again (after Fortra took over development from SecureAuthCorp), the path had changed to this:

- C\:\\Windows\\[a-zA-Z0-9]{8}.tmp

Now I would have to test the most recent version to see if the path changed, but we all know how threat actors likes to use old version of toolkits at time. So this may still be a good detection/hunting opportunity.

I'll update this query with a new regex, if there's indeed a new path (which may be in C:\Windows\Temp this time ...). And I should also check out NetExec (the successor of CME) to see how it looks...

Edit: Confirmed that it's indeed in C:\Windows\Temp (same file regex) now on NetExec 1.3.0 and Impacket 0.12.0.dev1. Added the new FolderPath regex to the query.

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

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessCommandLine has "RemoteRegistry"
| where FolderPath matches regex @'(?i)C\:\\Windows\\System32\\[a-zA-Z0-9]{8}.tmp'
  or FolderPath matches regex @'(?i)C\:\\Windows\\[a-zA-Z0-9]{8}.tmp'
  or FolderPath matches regex @'(?i)C\:\\Windows\\Temp\\[a-zA-Z0-9]{8}.tmp'
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessCommandLine has "RemoteRegistry"
| where FolderPath matches regex @'(?i)C\:\\Windows\\System32\\[a-zA-Z0-9]{8}.tmp'
  or FolderPath matches regex @'(?i)C\:\\Windows\\[a-zA-Z0-9]{8}.tmp'
  or FolderPath matches regex @'(?i)C\:\\Windows\\Temp\\[a-zA-Z0-9]{8}.tmp'
```
