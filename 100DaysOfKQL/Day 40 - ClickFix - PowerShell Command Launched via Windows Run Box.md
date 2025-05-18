# *ClickFix - PowerShell Command Launched via Windows Run Box*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/09 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1204.004 | User Execution: Malicious Copy and Paste | https://attack.mitre.org/techniques/T1204/004/ | 

#### Description

*Note: For more information about ClickFix, what is it, how it works, what kind of malware/threats it delivers, etc. refer to the articles linked in the References section before continuing

This query return events where a PowerShell command, with key emphasis on "command", was launched via the Windows Run box.

A nice little intersection between the world of EDR telemetry and forensics. The RunMRU Registry Key keeps track of commands that have been launched using the Windows Run box (Windows key + R). One of the ClickFix campaign variant instructs users to open that Run box (through the Start Menu, or simply the key combo), paste (Ctrl + V) the content of their clipboard in it and then press Enter. This will not only result in the execution of that PowerShell command, but also that command being written to the RunMRU Registry key of that user.

It is therefore possible to "hunt" or "detect" when a new Registry Value is set under that RunMRU Key which has the string "powershell" in it and from there, exclude these two (2) possibilities:

- powershell\1
- powershell.exe\1

With \1 acting as the end of the string, we know that if we can find the substring "powershell" and exclude these values, our results will be more likely to be commands (e.g.: powershell IWR "ifconfig.me/ip")

Alternatively, you can just run a query which looks for the string "powershell" in addition to one of any of the strings below, which are commonly used in these campaigns:

- Hidden
- IWR
- IEX
- Captcha
- reCAPTCHA
- Robot
- Invoke

I've also provided that query here.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape
- https://www.cyderes.com/blog/fake-gemini-security-alerts-lead-to-powershell-based-malware

### Queries Overview ###

- Defender for Endpoint (MDE) - 2 queries

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceRegistryEvents ###
```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where RegistryValueName != "MRUList"
| where RegistryValueData has "powershell"
| where RegistryValueData !in~ (@"powershell\1",@"powershell.exe\1")
```
### Microsoft Defender for Endpoint via DeviceRegistryEvents ###
```KQL
let InterestingStrings = dynamic([
    "Hidden",
    "IWR",
    "IEX"
    "Captcha",
    "reCAPTCHA",
    "Robot",
    "Invoke"
]);
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where RegistryValueName != "MRUList"
| where RegistryValueData has "powershell"
| where RegistryValueData has_any (InterestingStrings)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceRegistryEvents ###
```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where RegistryValueName != "MRUList"
| where RegistryValueData has "powershell"
| where RegistryValueData !in~ (@"powershell\1",@"powershell.exe\1")
```
### Microsoft Defender for Endpoint via DeviceRegistryEvents ###
```KQL
let InterestingStrings = dynamic([
    "Hidden",
    "IWR",
    "IEX"
    "Captcha",
    "reCAPTCHA",
    "Robot",
    "Invoke"
]);
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where RegistryValueName != "MRUList"
| where RegistryValueData has "powershell"
| where RegistryValueData has_any (InterestingStrings)
```
