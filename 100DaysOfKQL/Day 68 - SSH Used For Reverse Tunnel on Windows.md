# *SSH Used For Reverse Tunnel on Windows*

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/09 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1572 | Protcol Tunneling | https://attack.mitre.org/techniques/T1572/ |
| T1021.004 | Remote Services: SSH | https://attack.mitre.org/techniques/T1021/004/ |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events where SSH (on Windows) is used to set up a reverse tunnel.

PS: For more immediate context, threat actors can setup reverse tunnels to bypass network restrictions and from there, access systems remotely through other means, such as RDP (RDP through SSH tunnel).

#### Author <Optional>

- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://cloud.google.com/blog/topics/threat-intelligence/bypassing-network-restrictions-through-rdp-tunneling

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let SSHArgs = dynamic(["-R","@",":"]);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "ssh.exe"
    or InitiatingProcessCommandLine has_all (SSHArgs)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let SSHArgs = dynamic(["-R","@",":"]);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "ssh.exe"
    or InitiatingProcessCommandLine has_all (SSHArgs)
```
