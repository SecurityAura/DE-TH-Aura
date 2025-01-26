# *Suspicious Child Process Launched by Office Process*

## Query Information

This query returns events where a suspicious child process has been launched by a Microsoft Office process.

##

#### Description

This query returns events where a suspicious child process, from a pre-defined list has been launched by a Microsoft Office process (Word, Excel, PowerPoint, OneNote, Outlook).

This query is exactly as it looks like. A kind of, "back to the roots" query. From an era where SEO poisoning and complicated smuggling techniques were much less prevalent than the good ol' Office files with macros that ended up launching suspicious processes. They're not dead however, still quite active today. However, the number of these that actually make it past Email Security Gateways (is that how Gartner is calling them in 2025?) is a lot less than before. I can't even remember the last incident I had that originated from a malicious Office file.

As always, you can modify the list of "suspicious" child processes and Microsoft Office processes as you wish in the dynamic variables. You may even find some interesting, not suspicious/malicious stuff, in some environments. Like someone that has a macro in Excel which, when executed, would launch a PowerShell command with cleartext credentials, authenticating to a remote server to grab data files as input...

In term of references and/or how to enrich that query further, there's probably 10,000 variations of it on the Sigma Github repo. You can probably aggregate them all together to have "one query to rule them all" in the Office space.

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
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let SuspiciousChildProcesses = dynamic([
   "cmd.exe",
   "powershell.exe",
   "pwsh.exe",
   "wmic.exe",
   "cscript.exe",
   "wscript.exe",
   "mshta.exe",
   "rundll32.exe",
   "regsvr32.exe"
]);
let OfficeProcesses = dynamic([
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "onenote.exe"
    "outlook.exe"
]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (OfficeProcesses)
| where FileName in~ (SuspiciousChildProcesses)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let SuspiciousChildProcesses = dynamic([
   "cmd.exe",
   "powershell.exe",
   "pwsh.exe",
   "wmic.exe",
   "cscript.exe",
   "wscript.exe",
   "mshta.exe",
   "rundll32.exe",
   "regsvr32.exe"
]);
let OfficeProcesses = dynamic([
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "onenote.exe"
    "outlook.exe"
]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (OfficeProcesses)
| where FileName in~ (SuspiciousChildProcesses)
```
