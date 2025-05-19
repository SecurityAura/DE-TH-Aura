# *New Service Principal Added Following Consent to Application*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/14 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events where a new Service Principal is created in Entra ID following a user's consent to an application.

PS: For more immediate context, this is the kind of query which will return you new apps that are consented to by users in your tenant which didn't exist before, and where a Service Principal ends up being created. Think BEC scenarios where a threat actor leverages eM Client for instance.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Microsoft Sentinel (Entra ID) - 1 query

## Microsoft Sentinel ##
### Entra ID via AuditLogs ###
```KQL
let TargetOperations = dynamic([
    "Add app role assignment grant to user",
    "Add delegated permission grant",
    "Add service principal",
    "Consent to application"
]);
let NewServicePrincipalNames = (
AuditLogs
| where OperationName == "Add service principal"
| extend targetResources = parse_json(TargetResources)
| mv-apply tr = targetResources on (
    extend targetResource = tr.displayName
    | mv-apply mp = tr.modifiedProperties on (
    where mp.displayName == "DisplayName"
    | extend AppName = tostring(mp.newValue)
| distinct CorrelationId, AppName
))
);
AuditLogs
| where OperationName in~ (TargetOperations)
| extend User = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| summarize ["Operations"]=make_set(OperationName)
            by User, CorrelationId
| where Operations has_all (TargetOperations)
| join kind=inner NewServicePrincipalNames on CorrelationId
| project-reorder User, AppName, CorrelationId
```
