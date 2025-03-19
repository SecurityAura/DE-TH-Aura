# *Cloudflared Usage*

## Query Information

This query returns events where cloudflared was observed.

##

#### Description

This query returns events where cloudflared was observed through various means.

Cloudflared is a legitimate reverse proxy tool that can be used to create secure tunnels and whose main purpose is basically to expose endpoints and applications so that they can be used externally. The way the threat actors use it however, is also to set up reverse tunnels so that they can then remotely connect to these internal endpoints externally. One of their common use case is to setup a cloudflared agent on a compromised system and from the tunnel that has been set up, RDP into that system. Which is much more confortable to work with when you have access to a GUI at this point.

Sadly, the Cloudflared binary has no metadata associated to it, so it needs to be targeted by its default file name and/or process command line arguments.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a
- https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via union DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents ###
```KQL
union DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents
| where FileName has "cloudflared"
    or InitiatingProcessFilename has "cloudflared"
    or ProcessCommandLine has_all ("tunnel", "run", "--token")
    or InitiatingProcessCommandLine has_all ("tunnel", "run", "--token")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via union DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents ###
```KQL
union DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents
| where FileName has "cloudflared"
    or InitiatingProcessFilename has "cloudflared"
    or ProcessCommandLine has_all ("tunnel", "run", "--token")
    or InitiatingProcessCommandLine has_all ("tunnel", "run", "--token")
```
