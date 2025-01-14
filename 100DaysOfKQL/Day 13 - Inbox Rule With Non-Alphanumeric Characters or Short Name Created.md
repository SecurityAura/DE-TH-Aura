# *Inbox Rule With Non-Alphanumeric Characters or Short Name Created.*

## Query Information

This query return events were an Inbox Rule (in Exchange, Office 365) was created with a name that is only non-alphanumeric characters (e.g.: "..", "--", "-.-", etc.) or very short.

##

#### Description

This query return events were an Inbox Rule (in Exchange, Office 365) was created with a name that is only non-alphanumeric characters (e.g.: "..", "--", "-.-", etc.) or very short, for instance, less than 5 characters.

When threat actors compromise mailboxes in Business Email Compromise (BEC) incidents, they'll often create inbox rules to start hiding emails from the user. They can hide emails based on sender, sender domain, strings in the email subject or body, etc. The main goal behind this is for the threat actor to start interacting with these emails to setup a financial fraud of some kind. For instance, send to the victim new bank account information for their due invoice payment. Since these emails are hidden from the legitimate user, the fraud may just go unnoticed until the payment gets sent/transferred/etc.

Most of the time, these inbox rules will be created with either non-alphanumeric characters as name or with very short names (under 5 characters, even 1 or 2). The creation of inbox rules with non-alphanumeric characters is pretty atypical for normal users. As for inbox rules with really short names, it can happen, but when you review what the rule does, for instance, where the emails are moved (e.g.: RSS Feed, Conversation History, etc.), it makes it easy to determine if the hit is a true positive or a false positive.

There are two (2) versions of that query, one that leverages the Microsoft Defender for Cloud Apps (MCAS) table, while the other one leverages the OfficeActivity table from the Microsoft 365 connector in Microsoft Sentinel.

PS: These queries only focus on one aspect of a suspicious inbox rule: the name. There are other properties you could look into that may make a rule stand out as being suspicious/malicious. See the Expel.io blog post in the Reference(s) section.

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
| where TimeGenerated > ago(30d)
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
### Microsoft 365 via OfficeActivity
```KQL
let OperationTypes = dynamic([
    "New-InboxRule",
    "Set-InboxRule",
    "Enable-InboxRule"
]);
// You can adjust this value to tune-down possible false positives.
let RuleNameLength = 5;
OfficeActivity
| where Operation in~ (OperationTypes)
| mv-expand Params = todynamic(Parameters)
| where Params.Name in~ ("Name","RuleName")
| extend RuleName = Params.Value
| where isnotempty(RuleName)
| where RuleName matches regex @"^[^a-zA-Z0-9]*$"
    or strlen(RuleName) < RuleNameLength
```
