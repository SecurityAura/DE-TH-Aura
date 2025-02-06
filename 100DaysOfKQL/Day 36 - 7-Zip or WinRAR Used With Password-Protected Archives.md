# *7-Zip or WinRAR Used With Password-Protected Archives*

## Query Information

These queries returns events where 7-Zip or WinRAR is seen interacting with a password-protected archive.

##

#### Description

These queries returns events where 7-Zip or WinRAR is seen interacting with a password-protected archive based on the use of the "password" parameter.

It is no secret that threat actors likes to use archives, may it be for ingress (pull payloads or additional tools in a network) or egress (data exfil). Sometimes, they'll even password-protect these archives to protect them against prying eyes. For instance, prevent incident responders from grabbing an archive with their tools, scripts or payloads. Or prevent these same incident responders from being able to extract the content of an archive they created which hold data (e.g.: files) they collected from a system. Or even ... simply "ransom" companies using password-protected archives (https://news.sophos.com/en-us/2021/11/18/new-ransomware-actor-uses-password-protected-archives-to-bypass-encryption-protection/).

All in all, interacting with password-protected archives from the command line using 7-Zip or WinRAR may be unusual in some environments. Therefore, hunting or detecting this kind of activity could help you detect threat actors (or even malware) in your network going around, playing with these archives.

The good news is that, if you're able to detect this activity, it also means that you have the archive password in the event (telemetry). So if you can get your hands on whatever archive was involved, you can get its content by using the password.

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

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where (FileName in~ ("7z.exe","7zr.exe","7za.exe") and ProcessCommandLine contains " -p" and ProcessCommandLine has_any (" a "," x "))
    or (FileName in~ ("WinRAR.exe","RAR.exe") and ProcessCommandLine has_all ("a","-p"))
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where (FileName in~ ("7z.exe","7zr.exe","7za.exe") and ProcessCommandLine contains " -p" and ProcessCommandLine has_any (" a "," x "))
    or (FileName in~ ("WinRAR.exe","RAR.exe") and ProcessCommandLine has_all ("a","-p"))
```
