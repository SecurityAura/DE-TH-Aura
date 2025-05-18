# *Azure Subscription Ready Email*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/15 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1578 | Modify Cloud Compute Infrastructure | https://attack.mitre.org/techniques/T1578/ |

#### Description

This query returns events where a "New Azure Subscription is ready" email is sent to a user.

The actual title of this email, if I remember correctly (and based on what I could find online is): "Your Azure Subscription is ready".

What's the idea behind this query? Well, when a user within a tenant creates a new Azure subscription using the free $200 credit they're "entitled" too (https://azure.microsoft.com/en-ca/pricing/purchase-options/azure-account?icid=azurefreeaccount), they'll receive an email with that subject to tell them that their new Azure Subscription is ready.

While it is interesting to know if any of your users received emails because they actually went through that process themselves for whatever reason there is, do you know who also takes advantage of this? Threat Actors. In tenants where the ability to spin up new Azure Subscription is not disabled and/or restricted in some fashion, threat actors, once they compromise an account, can spin up a new Azure Subscription using that free $200 credit. From there, they've been observed spinning up resources such as VMs to conduct phishing campaigns against other organizations. And by "they've been" I mean, I also observed them doing so in a few mandates that started as BECs (Business Email Compromise).

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://learn.microsoft.com/en-us/microsoft-365/commerce/subscriptions/manage-self-service-signup-subscriptions?view=o365-worldwide

### Queries Overview ###

- Defender for Office 365 (MDO) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Office 365 via EmailEvents  ###
```KQL
EmailEvents
| where Subject =~ "Your Azure Subscription is ready"
// In case the wording of this email changes overtime, you could also use a combination of these three (3) words together just in case
//  or Subject has_all ("Azure","Subscription","Ready")
```
## Microsoft Sentinel ##
### Microsoft Defender for Office 365 via EmailEvents  ###
```KQL
EmailEvents
| where Subject =~ "Your Azure Subscription is ready"
// In case the wording of this email changes overtime, you could also use a combination of these three (3) words together just in case
//  or Subject has_all ("Azure","Subscription","Ready")
```
