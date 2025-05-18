# *Script Execution From User's Downloads Folder*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/11 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.002 | User Execution: Malicious File | https://attack.mitre.org/techniques/T1204/002/ |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |

#### Description

This query returns events where a user launched a script (BAT, PS1, JS, JSE, VB, VBE, VBS, etc.) from his Downloads folder. Typical phishing technique which is still around but probably less effective now. Basically, get a user to download a JS file masquerading as something else (fake browser update, SocGholish-like) and then execute it. It'll also work if a user download an archive (e.g.: ZIP) with a script inside, but extracted the content of the archive in the Downloads folder first, and then went in it and double-clicked to launch the script.

Most scripts will be executed with either wscript.exe or cscript.exe, except for the obvious BAT, CMD, PS1, and since the script is in the command line, we can look for events where it's located within a user's Downloads folder.

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

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
let ScriptInterpreters = dynamic([
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe"
    "cscript.exe",
    "wscript.exe"
]);
DeviceProcessEvents
| where FileName in~ (ScriptInterpreters)
| extend ScriptPath = extract(@"(?i)[aA-zZ]\:\\Users\\[^\\]+\\Downloads\\(.*)+\b",0,ProcessCommandLine)
| where isnotempty(ScriptPath)
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
let ScriptInterpreters = dynamic([
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe"
    "cscript.exe",
    "wscript.exe"
]);
DeviceProcessEvents
| where FileName in~ (ScriptInterpreters)
| extend ScriptPath = extract(@"(?i)[aA-zZ]\:\\Users\\[^\\]+\\Downloads\\(.*)+\b",0,ProcessCommandLine)
| where isnotempty(ScriptPath)
```
