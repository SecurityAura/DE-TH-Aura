# *Workstations with Public IP Assigned to Network Interface*

## Query Information

This query returns events where a workstation has a public IP address assigned to one of its network interfaces.

##

#### Description

This query returns events where a workstation (e.g.: Windows 10, Windows 11) has a public IP address assigned to one of its network interfaces. This information is actually readily available in the DeviceNetworkInfo table in the dynamic property IPAddresses column. It even tells us if an IP is public or private, how awesome is that!

The use case here is, I still see in 2024 (haven't seen it in 2025 yet but, it's just January), users that somehow ends up getting a public IP assigned to their endpoint (corporate ones, though they are not at the office). And what happens when a Windows device (servers aside too) is directly exposed to the Internet? There are so many correct answers here, you most likely guessed one of them.

Therefore, before this situation turns into an RDP bruteforcing alert, or an "Internet facing device" tag in MDE, you can actually look for this and get notified in almost real-time when a workstation gets assigned a public IP. This allows you to react right away, contact the user and possibly ask them to take a photo of how they're currently setup to have gotten that IP assignation.

If I had a penny for everytime I responded to that kind of incident, I would probably be able to buy an Arizona Tea (reference: https://x.com/DrinkAriZona/status/1882181201987035591)

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
### Microsoft Defender for Endpoint via DeviceInfo and DeviceNetworkInfo ###
```KQL
let Workstations = (DeviceInfo
| where DeviceType == "Server"
| distinct DeviceName);
DeviceNetworkInfo
| where DeviceName in~ (Workstations)
| mv-expand IPAddresses
| where IPAddresses.AddressType == "Public"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceInfo and DeviceNetworkInfo ###
```KQL
let Workstations = (DeviceInfo
| where DeviceType == "Server"
| distinct DeviceName);
DeviceNetworkInfo
| where DeviceName in~ (Workstations)
| mv-expand IPAddresses
| where IPAddresses.AddressType == "Public"
```
