# *Inbox Rule Involving Suspicious or Commonly Abused Folder*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/30 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1564.008 | Hide Artifacts: Email Hiding Rules | https://attack.mitre.org/techniques/T1564/008/ |

#### Description

This query return events were an Inbox Rule (in Exchange, Office 365) was created and involves a folder where threat actors often redirect emails as to hide them from the owner's inbox and/or other folders.

The goal here for the threat actor is to remain undetected in the mailbox and hide emails that would be part of chains the use to setup fraud (e.g.: send fake bank account information). It could also be to hide emails that would warn the user about the account compromise, by redirecting security alerts from the Help Desk, Microsoft, etc. in one of these folders.

A query whose goal is quite similar and/or would return similar events to the ones in "Inbox Rule With Non-Alphanumeric Characters or Short Name Created".

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://expel.com/blog/suspicious-outlook-rules-high-fidelity-patterns-to-watch-for/
- https://www.truesec.com/hub/blog/understanding-the-threat-what-is-business-email-compromise (Step 5 - Inbox Rules)
- https://www.huntress.com/blog/one-msp-three-microsoft-365-compromises-72-hours

### Queries Overview ###

- Microsoft Defender for Cloud Apps (MCAS) - 1 query
- Microsoft Sentinel - OfficeActivity (via Microsoft 365) - 1 query

## Defender XDR ##
### Microsoft Defender for Cloud Apps via CloudAppEvents ###
```KQL
let ActionTypes = dynamic([
    "New-InboxRule",
    "Set-InboxRule",
    "Enable-InboxRule"
]);
// You can adjust this value to tune-down possible false positives.
let RuleNameLength = 5;
CloudAppEvents
| where ActionType in~ (ActionTypes)
| mv-expand ActObj = ActivityObjects
| where ActObj.Name in~ ("Name","RuleName")
| extend RuleName = ActObj.Value
| where isnotempty(RuleName)
| where RuleName matches regex @"^[^a-zA-Z0-9]*$"
    or strlen(RuleName) < RuleNameLength
```
## Microsoft Sentinel ##
### Microsoft Defender for Cloud Apps via CloudAppEvents ###
```KQL
let InboxRuleActionTypes = dynamic([
    "New-InboxRule",
    "Set-InboxRule",
    "Enable-InboxRule",
    "UpdateInboxRules"
]);
let Folders = dynamic([
    "Archive",
    "Conversation History",
    "RSS"
]);
CloudAppEvents
| where ActionType in (InboxRuleActionTypes)
| where ActivityObjects has_any (Folders)
```
### Microsoft 365 via OfficeActivity
```KQL
let InboxRuleOperations = dynamic([
    "New-InboxRule",
    "Set-InboxRule",
    "Enable-InboxRule",
    "UpdateInboxRules"
]);
let Folders = dynamic([
    "Archive",
    "RSS",
    "Conversation History"
]);
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in (InboxRuleOperations)
| where Parameters has_any (Folders)
```
