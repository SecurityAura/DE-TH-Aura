# *Windows Remote Management Command Targeting a Remote Endpoint*

## Query Information

This query returns events where a Windows Remote Management (WinRM) command is targeting a remote endpoint.

##

#### Description

This query returns events where a Windows Remote Management (WinRM) command is targeting (read: used against) a remote endpoint.

Windows Remote Management or WinRM is, as the name implies, Microsoft's implementation of the WS-Management protocol. To put it simply, in the context of our queries and what we're looking for here: it allows you to execute commands, start programs, etc. on Windows systems, may it be the local system (where the command is run from) or a remote system (which the command would target).

There are multiple ways to launch commands against remote endpoints using Windows Remote Management. The most known, and therefore, common ones are:

- wmic.exe - The WMI Command-Line Utility
- winrs.exe - A utility similar to wmic.exe
- PowerShell Remoting (which leverages Windows Remote Management)

Each of these allow you to execute command on remote endpoints, assuming the Windows Remote Management service (WinRM) is not disabled. 

- For winrs.exe, the WinRM service needs to be running
- For PowerShell Remoting, it needs to be enabled first (Enable-PSRemoting), which will configure the system with a listener to accept inbound connections and set the WinRM service start type to "Automatic (Delayed)" alongside starting it.

From there, it's just a matter of targeting a remote endpoint with arbitrary commands of your choice (well, the threat actor's choice).

PS: Maybe there will be an upcoming #100DaysOfKQL day showing how to spot these incoming remote commands from the target system POV, who knows!

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://lolbas-project.github.io/lolbas/Binaries/Wmic/
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs
- https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.5

### Queries Overview ###

- Defender for Endpoint (MDE) - 2 queries

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Enter-PSSession", "New-PSSession", "Invoke-Command")
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where (FileName =~ "winrs.exe" and ProcessCommandLine has_any ("/r:", "/remote:")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("Enter-PSSession", "New-PSSession", "Invoke-Command")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Enter-PSSession", "New-PSSession", "Invoke-Command")
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where (FileName =~ "winrs.exe" and ProcessCommandLine has_any ("/r:", "/remote:")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("Enter-PSSession", "New-PSSession", "Invoke-Command")
```
