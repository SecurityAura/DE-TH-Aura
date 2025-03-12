# *Potential Terminal Server or TermService Tampering via RDPWrap*

## Query Information

This query returns events where the Terminal Server or TermService may have been tampered with via RDPWrap.

##

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events where the Terminal Server or TermService may have been tampered with via RDPWrap.

PS: For more immediate context, RDPWrap is used by threat actors' (mostly script kiddies "à la" Phobos however) to patch the Terminal Server/TermService on a Windows system and allow stuff such as concurrent session (which means, if 2 users are already logged in for instance, a 3rd one, the TA could login without prompted the other two to disconnect).

PS 2: This behavior MAY already be detected by Defender for Endpoint (MDE) as a built-in rule. Been a while since I last tested it.

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
### Microsoft Defender for Endpoint via DevicRegistryEvents ###
```KQL
DeviceRegistryEvents
| where RegistryKey has_any (@"Control\Terminal Server\Licensing Core",@"Services\TermService\Parameters")
    or (RegistryKey =~ @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        and RegistryValueName == "AllowMultipleTSSessions")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DevicRegistryEvents ###
```KQL
DeviceRegistryEvents
| where RegistryKey has_any (@"Control\Terminal Server\Licensing Core",@"Services\TermService\Parameters")
    or (RegistryKey =~ @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        and RegistryValueName == "AllowMultipleTSSessions")
```
