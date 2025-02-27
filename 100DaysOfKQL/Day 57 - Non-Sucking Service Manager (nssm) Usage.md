# *Non-Sucking Service Manager (nssm) Usage*

## Query Information

This query returns events where the Non-Sucking Service Manager (nssm) application was observed.

##

#### Description

DISCLAIMER: I once again have to put up that query of the day very fast today. I'll come back to it to add more queries to hunt for NSSM.

This query returns events where the Non-Sucking Service Manager (nssm) application was observed. NSSM is a popular little application (free, the way we like them) that allows you to basically turn anything into a service, may it be a binary, script, command, etc. If you read between the lines of the previous sentence, you'll quickly understand that NSSM can also be abused by threat actors to basically persist in the form of a service. May it be a backdoor, ransomware, BYVOD, etc.

For instance, threat actors can use NSSM with ngrok (Day 56 query), even though ngrok can be installed as a service by itself, to make sure that the ngrok agent constantly stays up and running and restarted even after reboot, the process gets killed, the process crashes, etc.

NSSM has also been seen to persisently launch coinminers such as XMRig on compromised systems.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://nssm.cc/
- https://news.sophos.com/en-us/2023/12/21/akira-again-the-ransomware-that-keeps-on-taking/
- https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/

### Queries Overview ###

- Defender for Endpoint (MDE) - 3 queries
- Microsoft Sentinel (via SecurityEvent and Event) - 2 queries TO BE ADDED

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "nssm.exe" 
    or InitiatingProcessFileName =~ "nssm.exe"
```
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FileName =~ "nssm.exe"
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| where FileName =~ "nssm.exe" 
    or FolderPath has "nssm"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "nssm.exe" 
    or InitiatingProcessFileName =~ "nssm.exe"
```
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FileName =~ "nssm.exe"
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| where FileName =~ "nssm.exe" 
    or FolderPath has "nssm"
```
