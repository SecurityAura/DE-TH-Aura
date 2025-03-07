# *Network Connections Coming From VPN Ranges*

## Query Information

This query returns events where a network connection comes from an IP address located in a VPN range.

##

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query. You can add as many VPN ranges are you want, assuming you have more than one, e.g.: multiple locations.

This query returns events where a network connection comes from an IP address located in a VPN range.

PS: For more immediate context, this kind of query can give you a quick idea of whether any network segmentation is in place between the VPN (or various VPN) range(s) or not. For instance, Accounting users that VPN in the network shouldn't be able to reach management ports of servers (e.g.: 3389/RDP) such as Domain Controllers. Depending on the events that are being returned, you may be dealing with a rogue endpoint in the VPN range.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 2 queries
- Defender for Identity (MDI) - Coming later

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let VPNRanges = dynamic([
    "192.168.100.0/24",
    "192.168.200.0/24"
]);
DeviceNetworkEvents
| where ActionType == "InboundConnectionAccepted"
| where ipv4_is_in_any_range( RemoteIP, VPNRanges)
| summarize ["LocalPorts"]=make_set(LocalPort),
            ["LocalPortCount"]=dcount(LocalPort),
            ["RemoteIPs"]=make_set(RemoteIP),
            ["RemoteIPCount"]=dcount(RemoteIP)
            by DeviceName, LocalIP
```
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
let VPNRanges = dynamic([
    "192.168.100.0/24",
    "192.168.200.0/24"
]);
DeviceLogonEvents
| where ipv4_is_in_any_range( RemoteIP, VPNRanges)
| summarize ["RemoteIPs"]=make_set(RemoteIP),
            ["RemoteIPCount"]=dcount(RemoteIP)
            by DeviceName
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let VPNRanges = dynamic([
    "192.168.100.0/24",
    "192.168.200.0/24"
]);
DeviceNetworkEvents
| where ActionType == "InboundConnectionAccepted"
| where ipv4_is_in_any_range( RemoteIP, VPNRanges)
| summarize ["LocalPorts"]=make_set(LocalPort),
            ["LocalPortCount"]=dcount(LocalPort),
            ["RemoteIPs"]=make_set(RemoteIP),
            ["RemoteIPCount"]=dcount(RemoteIP)
            by DeviceName, LocalIP
```
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
let VPNRanges = dynamic([
    "192.168.100.0/24",
    "192.168.200.0/24"
]);
DeviceLogonEvents
| where ipv4_is_in_any_range( RemoteIP, VPNRanges)
| summarize ["RemoteIPs"]=make_set(RemoteIP),
            ["RemoteIPCount"]=dcount(RemoteIP)
            by DeviceName
```
