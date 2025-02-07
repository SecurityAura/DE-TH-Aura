# *Net.exe Use Against a Remote External ComputerName*

## Query Information

This query return events where the net.exe use command was used against a remote, external ComputerName.

##

#### Description

*Note: The term "ComputerName" here is used because it is actually the name of the parameter in the "net.exe use" context:

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v=ws.11)

This query return events where the net.exe use command was used against a remote, external ComputerName, may it be a FQDN or an IP address.

The idea behind this query is to catch this kind of behavior:

https://x.com/filescan_itsec/status/1886739550673707322

Now that malware and even threat actors (*cough*APT*cough*) are abusing WebDAV, this query can be used either as a detection or a threat hunting query to find instances of a "net.exe use" command where a remote ComputerName has been used. From there, you'll want to investigate/determine what is that ComputerName:

- Is it legit (e.g.: some organizations will use Azure SMB file shares: https://learn.microsoft.com/en-us/azure/storage/files/files-smb-protocol?tabs=azure-portal)
- If not, what caused that command to be executed (user-initiated, script-initiated, etc.)
- What lies at the end of that connection (e.g.: what files, folders, etc. are present in that remote share)
- And more

The query may need to be tweaked if you run it in an environment where multiple FQDNs are used internally (e.g.: olddomain.local, newdomain.local). It is just a matter of changing how the filter condition works or chaining as many as needed with new variables and adding filters.

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

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
// Taken fom Bert-Jan with love: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/KQL%20Regex/RegexExamples.md
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let FQDN = "YOUR_FQDN_HERE";
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName =~ "net.exe"
| where ProcessCommandLine has_all ("use","\\\\")
// Extracting the ComputerName from the ProcessCommandLine (e.g.: \\SERVER1\, \\192.168.10.100\, \\NAS.DOMAIN.LOCAL\, etc.)
| extend ComputerName = extract(@"(?i)\\\\([^\\]+)\\",1,ProcessCommandLine)
// Ensuring we only keep ComputerName with dots so IP addresses and FQDNs
| where ComputerName has "."
// Create a new field which will tell us if the ComputerName is an IP address or a FQDN
| extend ComputerNameType = iif(ComputerName matches regex IPRegex, "IP", "FQDN")
| extend IPType = iif((ComputerNameType == "IP" and ipv4_is_private( ComputerName)), "Private", "Public")
// Filter out connections to ComputerNames where the FQDN ends with our internal FQDN
| where ComputerName !endswith FQDN
// Filter out private IP addresses (internal use)
| where IPType != "Private
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
// Taken fom Bert-Jan with love: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/KQL%20Regex/RegexExamples.md
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let FQDN = "YOUR_FQDN_HERE";
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName =~ "net.exe"
| where ProcessCommandLine has_all ("use","\\\\")
// Extracting the ComputerName from the ProcessCommandLine (e.g.: \\SERVER1\, \\192.168.10.100\, \\NAS.DOMAIN.LOCAL\, etc.)
| extend ComputerName = extract(@"(?i)\\\\([^\\]+)\\",1,ProcessCommandLine)
// Ensuring we only keep ComputerName with dots so IP addresses and FQDNs
| where ComputerName has "."
// Create a new field which will tell us if the ComputerName is an IP address or a FQDN
| extend ComputerNameType = iif(ComputerName matches regex IPRegex, "IP", "FQDN")
| extend IPType = iif((ComputerNameType == "IP" and ipv4_is_private( ComputerName)), "Private", "Public")
// Filter out connections to ComputerNames where the FQDN ends with our internal FQDN
| where ComputerName !endswith FQDN
// Filter out private IP addresses (internal use)
| where IPType != "Private
```
