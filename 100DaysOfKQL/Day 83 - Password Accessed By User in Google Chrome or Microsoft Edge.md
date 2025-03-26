# *Password Accessed By User in Google Chrome or Microsoft Edge*

## Query Information

This query returns events where a password saved in the Password Manager was potentially accessed by a user.

##

#### Description

DISCLAIMER - I have to post this query quickly today. I'll comeback to it and update it with more information later on.

This query returns events where a password saved in the Password Manager was potentially accessed by a user.

Chromium-based Web browsers such as Google Chrome and Microsoft Edge encrypt/protect the passwords saved in the Password Manager feature. When you try to access an account that was saved there, you're prompted for your credentials to confirm that you can access them. Entering your credentials successfully results in the access of that account within the Password Manager from which you can display/show the saved password if needed.

This generates an Interactive (Logon Type 2) successful logon event from the user that logged in from the Web Browser process, e.g.: chrome.exe or msedge.exe.

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
- Microsoft Sentinel (SecurityEvent) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType == "Interactive"
| where not (AccountName endswith "$")
| where not (InitiatingProcessAccountName endswith "$")
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType == "Interactive"
| where not (AccountName endswith "$")
| where not (InitiatingProcessAccountName endswith "$")
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe")
```
### Microsoft Sentinel via SecurityEvent ###
```KQL
SecurityEvent
| where EventID == 4624
| where LogonType == 2
| where not (TargetAccount endswith "$")
| where not (SubjectAccount endswith "$")
| where Process in~ ("msedge.exe","chrome.exe")
```
