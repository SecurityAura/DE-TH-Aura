# *Events Initiated From Targeted Remote DeviceName or SessionIP*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/10 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

#### Description

This query return events that are associated with a remote connection (read: Remote Desktop Protocol or RDP) associated with a defined (known) DeviceName or SessionIP.

Thanks to the addition of RDP session data to the various Defender for Endpoint (MDE) tables last summer (see References section below), we can now hunt for events (processes, network connection, file events, etc.) that were generated during specific RDP sessions!

This is useful in incidents where you know the hostname of the device and/or IP of the device the threat actor used to RDP on certain systems and from there, "dump" all the events related to their activity on these systems.

You can identify these hostnames and/or IPs in a few ways, the easiest one being to query DeviceLogonEvents first to identify suspicious RemoteDeviceName and RemoteIP.

NOTE: Be careful with the RemoteIP field, since it'll also match DeviceNetworkEvents and/or DeviceEvents where network connections involving these IPs are observed. So be sure to properly assess the significance of these events before including them in your analysis.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/detect-compromised-rdp-sessions-with-microsoft-defender-for-endpoint/4201003

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via everything ###
```KQL
let RemoteDeviceNames = dynamic([
    "ADD",
    "DEVICENAMES"
    "OF INTEREST",
    "HERE"
]);
let RemoteIPs = dynamic([
    "ADD",
    "REMOTE IPs"
    "OF INTEREST",
    "HERE"
]);
union DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents
| where InitiatingProcessRemoteSessionDeviceName in~ (RemoteDeviceNames)
    or InitiatingProcessRemoteSessionIP in (RemoteIPs)
    or ProcessRemoteSessionDeviceName in~ (RemoteDeviceNames)
    or ProcessRemoteSessionIP in (RemoteIPs)
    or RemoteDeviceName in~ (RemoteDeviceNames)
    or RemoteIP in (KnownRemoteIPs)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via everything ###
```KQL
let RemoteDeviceNames = dynamic([
    "ADD",
    "DEVICENAMES"
    "OF INTEREST",
    "HERE"
]);
let RemoteIPs = dynamic([
    "ADD",
    "REMOTE IPs"
    "OF INTEREST",
    "HERE"
]);
union DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents
| where InitiatingProcessRemoteSessionDeviceName in~ (RemoteDeviceNames)
    or InitiatingProcessRemoteSessionIP in (RemoteIPs)
    or ProcessRemoteSessionDeviceName in~ (RemoteDeviceNames)
    or ProcessRemoteSessionIP in (RemoteIPs)
    or RemoteDeviceName in~ (RemoteDeviceNames)
    or RemoteIP in (KnownRemoteIPs)
```
