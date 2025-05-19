# *CScript.exe, WScript.exe or MSHTA.exe Executed from Web Browser Process*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/04/12 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |
| T1204.002 | User Execution: Malicious File | https://attack.mitre.org/techniques/T1204/002/ |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |

#### Description

This query returns events where a script interpreter (cscript.exe, wscript.exe or mshta.exe) was executed from a Web browser process.

The logic here is similar from the one from Day 11 query, however, there's one big difference. The event we're targeting here is one where the user would straight up download a script file that can get executed by cscript.exe, wscript.exe or mshta.exe on execution (e.g.: VB, VBE, VBS, JS, JSE, WS, WSE, etc.).

This is typically what you would see when a user downloads such a file (e.g.: ChromeUpdate2025.js) and then open it from the Web browser interface (e.g.: click on it from the Downloads view in Google Chrome). And this is exactly how some malware still ... "behave" to this day:

https://www.googlecloudcommunity.com/gc/Community-Blog/Finding-Malware-Detecting-Fake-Browser-Updates-Attacks-with/ba-p/876307

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
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
]);
let WebBrowsers = dynamic([
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe"
]);
DeviceProcessEvents
| where FileName in~ (ScriptInterpreters)
| where InitiatingProcessFileName in~ (WebBrowsers)
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
let ScriptInterpreters = dynamic([
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
]);
let WebBrowsers = dynamic([
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe"
]);
DeviceProcessEvents
| where FileName in~ (ScriptInterpreters)
| where InitiatingProcessFileName in~ (WebBrowsers)
```
