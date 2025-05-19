# *Consent to Application With Dangerous Delegated Permissions*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/16 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events where a user consents to an application with dangerous delegated permissions.

PS: For more immediate context, this query uses LETHAL-FORENSICS's Microsoft-Analyzer-Suite Delegated Permissions Blacklist to look for events where a user consents to an app with dangerous delegated permissions. As it is right now, the application only looks for permissions with a "High" Severity rating, though this can be removed if needed.
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/tree/main (https://x.com/LETHAL_DFIR)

### Queries Overview ###

- Microsoft Sentinel (Microsoft Entra ID) - 1 query

## Microsoft Sentinel ##
### Microsoft Entra ID via AuditLogs ###
```KQL
let DangerousDelegatedPermissions =
    externaldata ( Permission: string, PermissionType: string, DisplayText: string, AdminConsentRequired: string, Severity: string)
        ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/DelegatedPermission-Blacklist.csv"]
        with (format=csv, ignoreFirstRecord=true)
        | where Severity == "High"
        | distinct Permission;
AuditLogs
| where OperationName == "Consent to application"
| extend targetResources = parse_json(TargetResources)
| mv-apply tr = targetResources on (
    extend targetResource = tr.displayName
    | mv-apply mp = tr.modifiedProperties on (
    where mp.displayName == "ConsentAction.Permissions"
    | extend ConsentActionPermissions = tostring(mp.newValue)))
| parse ConsentActionPermissions with * "Scope: " ExtractedPermissions "," *
| extend Permissions = split(ExtractedPermissions, " ")
| where Permissions has_any (DangerousDelegatedPermissions)
```
