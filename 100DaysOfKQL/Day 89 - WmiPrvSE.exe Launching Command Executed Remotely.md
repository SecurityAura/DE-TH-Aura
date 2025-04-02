# *WmiPrvSE.exe Launching Command Executed Remotely*

## Query Information

This query returns events WmiPrvSE.exe (Windows Management Instrumentation) launched a command executed remotely.

##

#### Description

This query returns events WmiPrvSE.exe (Windows Management Instrumentation) launched a command executed remotely.

The query below is a deeper dive on this bullet point from Day 51 query (therefore, refer to its description for what you're looking for here and how it can be (ab)used by threat actors):

- wmic.exe leads to WmiPrvSE.exe launching the command on the target

In Defender for Endpoint (MDE), this specific process execution can actually be found in its own ActionType of ProcessCreatedUsingWmiQuery within the DeviceEvents table. What if you don't have MDE however? Well, it is still possible to link the execution of a process (e.g.: cmd.exe) to WmiPrvSE.exe if that command was launched remotely by linking the TargetLogonId of the EID 4688 (Process Creation Event) and a EID 4624 (Successful Logon) with a Network Logon (Logon Type 3).

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Microsoft Sentinel (SecurityEvent) - 1 query

## Microsoft Sentinel ##
### Microsoft Sentinel via SecurityEvent ###
```KQL
let RemoteWmiProcessEvents = (SecurityEvent
| where EventID == 4688
| where ParentProcessName has "wmiprvse.exe"
| where NewProcessName has "cmd.exe");
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| join kind=inner RemoteWmiProcessEvents on Computer, TargetLogonId
```
