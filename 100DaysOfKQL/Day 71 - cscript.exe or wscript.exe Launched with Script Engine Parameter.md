# *cscript.exe or wscript.exe Launched with Script Engine Parameter*

## Query Information

This query returns events where cscript.exe or wscript.exe is launched with the "script engine" parameter.

##

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events where cscript.exe or wscript.exe is launched with the "script engine" parameter.

PS: For more immediate context, it used to be pretty popular back in the day to launch cscript.exe or wscript.exe that way. It may still be today with Gootkit/Gootloader but it's been a while since I've dealt with it. This isn't the kind of invocation you may see often in an environment. And the use of the /E: parameter is most commonly associated with using the JScript engine.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://www.crowdstrike.com/en-us/blog/hunting-for-malicious-jscript-with-overwatch-elite/
- https://www.sentinelone.com/labs/deep-insight-into-fin7-malware-chain-from-office-macro-malware-to-lightweight-js-loader/
- https://www.uptycs.com/blog/threat-research-report-team/understanding-stealerium-malware-and-its-evasion-techniques

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("cscript.exe", "wscript.exe")
| where ProcessCommandLine has_any ("//E:", "/E:")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("cscript.exe", "wscript.exe")
| where ProcessCommandLine has_any ("//E:", "/E:")
```
