# *System Time Manipulation - Retrosigned Drivers EDR Bypass*

## Query Information

Per an article from Aon Stroz Friedberg from September 2024, ransomware actors have been observed manipulating system time on endpoints in order to bypass the EDR.

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | https://attack.mitre.org/techniques/T1059/003/ |
| T1489 | ServiceStop | https://attack.mitre.org/techniques/T1489/ |

#### Description

This rule detects either step in a chain of three (3) commands used to manipulate the system time on an endpoint:

- net.exe to stop the w32time service
- w32tm.exe to unregister the time service
- PowerShell to change the system date/time

#### Risk
Explain what risk this detection tries to cover

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### References
- https://www.aon.com/en/insights/cyber-labs/bypassing-edr-through-retrosigned-drivers-and-system-time-manipulation
- https://x.com/StrozDFIR/status/1835796156368195897 (Original Tweet)
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ff799054(v=ws.11)
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/set-date?view=powershell-7.4

## Defender XDR
```KQL
DeviceProcessEvents
| where FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has_all ("stop","w32time")
    or FileName =~ "w32tm.exe" and ProcessCommandLine has ("unregister")
    or FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has ("Set-Date")
```
## Sentinel
```KQL
DeviceProcessEvents
| where FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has_all ("stop","w32time")
    or FileName =~ "w32tm.exe" and ProcessCommandLine has ("unregister")
    or FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has ("Set-Date")
```
