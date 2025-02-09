# *Windows Event Logs Cleared*

## Query Information

This query return events where Windows Event Logs were cleared.

##

#### Description

This query return events where Windows Event Logs were cleared through wevtutil.exe, PowerShell or from the specific Event IDs this action leaves behind.

One of the worst thing a threat actor can do in an intrusion to hinder the follow-up investigation (or response) is clear the Windows Event Logs. When hitting organizations that do not even have any kind of logging in place (think EDR, Event ID 4688, Sysmon, SIEM, etc.), the Windows Event Log becomes a goldmine of information. And when that goldmine is just blasted away shut, it hurts.

The two (2) most popular ways to clear Windows Events Logs are:

- Through wevtutil.exe (https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- Through PowerShell Clear-EventLog cmdlet(https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog?view=powershell-5.1)

Luckily for us, we can easily detect and/or hunt for these in Defender for Endpoint (MDE). 

When clearing the Security Event Log, a helpful Event ID 1102 (The audit log was cleared) will also be generated. This event also contains information about who cleared the event log, such as the Account Domain, Account Name and Logon ID. Should you have access to previous events of the Security Event Log before it was cleared (e.g.: they were sent to a SIEM such as Microsoft Sentinel), you can then associate that Logon ID to an Event ID 4624 (Successful logon) and try to get more insight into where that user came from.

Should you create a detection for that behavior, you better be ready to react fast. In typical ransomware attacks, clearing the Windows Event Log is one of the last step a threat actor go through before deploying the ransomware (e.g.: one of the command in the ransomware deployment script). Before or after deleting all the volume shadow copies on a system too.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-find-ransomware (found this while looking for references and saw that it has a lot of neat little Threat Hunting queries, including one for Windows Event Log clear!)
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a
- https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in/

### Queries Overview ###

- Defender for Endpoint (MDE) - 2 queries
- Microsoft Sentinel (SecurityEvent) 1 - query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "Clear-EventLog"
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl","clear-log"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Clear-EventLog")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "Clear-EventLog"
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl","clear-log"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Clear-EventLog")
```
### SecurityEvent ###
```KQL
SecurityEvent
| where EventID == 1102
```
