# *OfficeActivity - MailItemsAccessed Breakdown*

## Description

The queries below can be used to obtain information about MailItemsAccessed events from flagged IP addresses.

There are two (2) types of MailAccessType: Bind and Sync. Bind events refers to single access to an email (e.g.: email viewed in OWA) while Sync events refers (technically) to the download of an email by a Microsoft Outlook client on either Windows or macOS (though this could be challenged).

https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts

In BEC incidents, if you want to know which emails were accessed by a threat actor, you'll want to look into and breakdown these MailItemsAccessed events.

## Prerequisite(s) #

A list of IP addresses that you identified as being malicious, suspicious and/or of interest.

## Microsoft Sentinel
### Query #1 - List of emails (InternetMessageId) involved in Bind operations

This query will give you the list of emails, by their unique InternetMessageId that were involved in Bind operations by UserId. You should assume, per Microsoft's documentation, that any email listed in this output has been accessed by an unauthorized third-party and therefore, leaked/exfiltrated.

```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| where Operation == "MailItemsAccessed"
| extend MailAccessType = tostring(parse_json(OperationProperties)[0].Value)
| where MailAccessType == "Bind"
| extend FolderItems = parse_json(Folders)
| mv-expand todynamic ( FolderItems) 
| mv-expand todynamic ( parse_json(FolderItems).FolderItems)
| extend FolderName = tostring(parse_json(FolderItems).Path)
| extend InternetMessageId = tostring(parse_json(FolderItems_FolderItems).InternetMessageId)
| summarize ["Folders"]=make_set(FolderName),
            ["Number of Folders"]=dcount(FolderName)
            by InternetMessageId, UserId
```
### Query #2 - List of Folders involved in Sync operations

This query will give you the list of Folders that were involved in Sync operations by UserId. You should assume, per Microsoft's documentation, that the content of any Folder listed in this output has been fully synchronized externally and therefore, the emails exfiltrated.

```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| where Operation == "MailItemsAccessed"
| extend MailAccessType = tostring(parse_json(OperationProperties)[0].Value)
| where MailAccessType == "Sync"
| extend SyncedFolderName = tostring(parse_json(parse_json(Item).ParentFolder).Name)
| extend SyncedFolderPath = tostring(parse_json(parse_json(Item).ParentFolder).Path)
| distinct MailAccessType, SyncedFolderName, SyncedFolderPath, UserId
```
