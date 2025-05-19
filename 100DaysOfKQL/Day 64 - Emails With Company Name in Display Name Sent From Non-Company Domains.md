# *Emails With Company Name in Display Name Sent From Non-Company Domains*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/05 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query. You also may need to exclude more domains if you use services that send emails from their domains/stack but use your name, such as Jira, Amazon SES, Adobe Sign, etc.

This query returns events where an email was sent to organization's users where the company name is in the display name, but that email doesn't originate from that company's domains and where the email was not blocked.

PS: For more immediate context, this is a query I used to find multiple QR-code phishing emails targeting an organization where they were let through by MDO. 

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Office 365 (MDO) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Office 365 via EmailEvents ###
```KQL
let CompanyNames = dynamic([
    "CompanyName"
]);
let OrgDomains = dynamic([
    "CompanyDomainA.com",
    "CompanyDomainB.net"
]);
EmailEvents
| where SenderDisplayName has_any (CompanyNames)
| where SenderFromDomain !in~ (OrgDomains)
    and SenderMailFromDomain !in~ (OrgDomains)
| where DeliveryAction != "Blocked"
```
## Microsoft Sentinel ##
### Microsoft Defender for Office 365 via EmailEvents ###
```KQL
let CompanyNames = dynamic([
    "CompanyName"
]);
let OrgDomains = dynamic([
    "CompanyDomainA.com",
    "CompanyDomainB.net"
]);
EmailEvents
| where SenderDisplayName has_any (CompanyNames)
| where SenderFromDomain !in~ (OrgDomains)
    and SenderMailFromDomain !in~ (OrgDomains)
| where DeliveryAction != "Blocked"
```
