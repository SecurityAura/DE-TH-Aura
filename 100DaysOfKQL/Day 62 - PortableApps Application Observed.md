# *PortableApps Application Observed*

## Query Information

This query returns events where a PortableApps application was observed.

##

#### Description

This query returns events where a PortableApps application (.paf.exe extension) was observed.

"Portable Apps", typically associated with PortableApps.com are "self contained" applications that are installed within an arbitrary folder by an installer. It allows you to download and use applications without having to install them, and that can be basically "live" within the folder they are "installed" in, without interfacing with the Windows Registry or else. Everything they need to work: configuration, settings, files, etc. are in their "installation" folder.

In a certain way, you can see portable apps as a way to "bypass" installation restrictions, since you can "install" an application in a folder of your choosing, and it would not be subject to certain restrictions that are in place, such as GPOs that are acting/enforcing certain Registry Keys.

Threat actors have been observed using portable apps (.paf.exe) in certain attacks, though it does not seem to be that popular. Even I can probably only count on one hand the number of ransomware-related IRs where I've seen such apps being used. Even though at least one of these fingers would be used for a ransomware engagement in 2025.

In Defender for Endpoint (MDE), you can look for portable apps through their distinctive ".paf.exe" extension (which is just an .exe, with a .paf appended in the filename) and/or the files being downloaded from PortableApps.com.

PS: If while you're hunting for these, you find a user using a portable version of a Web Browser, in a corporate setting, you may want to ask them what they are trying to achieve.

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

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FileName endswith ".paf.exe"
    or FileOriginUrl has "portableapps.com"
    or FileOriginReferrerUrl has "portableapps.com"
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName endswith ".paf.exe"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FileName endswith ".paf.exe"
    or FileOriginUrl has "portableapps.com"
    or FileOriginReferrerUrl has "portableapps.com"
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName endswith ".paf.exe"
```
