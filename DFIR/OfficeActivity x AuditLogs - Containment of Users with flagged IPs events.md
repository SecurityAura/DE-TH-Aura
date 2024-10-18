# *OfficeActivity x AuditLogs - Containment of Users with flagged IPs events*

## Description

The query below can assist in getting a summary of the containment actions taken on users who had activities from flagged IP addresses.

It works by getting a list of all users who had OfficeActivity events from a predefined list of flagged IP addresses and from there, cross-reference them in the AuditLogs table to see if various containment actions (e.g.: password reset, account disable, etc.) was taken.

## Prerequisite(s) #

- A list of IP addresses that you identified as being malicious, suspicious and/or of interest.
- Ajust the timerange for the period of time that covers both the incident and the containment actions that would have been taken

## Microsoft Sentinel
### Query #1 - OfficeActivity x AuditLogs - Containment of Users with flagged IPs events
```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
let CompromisedUsers = (
    OfficeActivity
    | where ClientIP has_any (FlaggedIPs)
        or Client_IPAddress has_any (FlaggedIPs)
        or ActorIpAddress has_any (FlaggedIPs)
    | distinct UserId
);
AuditLogs
| where OperationName in~ ("Disable account","Reset user password","Reset password (self-service)","Reset password (by admin)")
| extend Id = tostring(parse_json(TargetResources)[0].id)
| extend TargetUPN = tostring(parse_json(TargetResources)[0].userPrincipalName)
| join kind=rightouter CompromisedUsers on $left.TargetUPN == $right.UserId
| summarize ["Operations"] = make_set(OperationName)
            by UserId
| extend AccountDisabled = iif(Operations has "Disable account", "Yes", "No")
| extend AccountPasswordReset = iif(Operations has "Reset user password", "Yes", "No")
| extend AccountPasswordResetBySelfService = iif(Operations has "Reset password (self-service)", "Yes", "No")
| extend AccountPasswordResetByAdmin = iif(Operations has "Reset password (by admin)", "Yes", "No")
| extend AtLeastOnePasswordResetOperation = iif (Operations has "password", "Yes", "No")
| project UserId, AccountDisabled, AccountPasswordReset, AccountPasswordResetBySelfService, AccountPasswordResetByAdmin, AtLeastOnePasswordResetOperation
```
