# *OfficeActivity - Emails involved in Operations from flagged IPs.md*

## Description

The queries below can be used to obtain information about about emails that were involved in events coming from flagged IP addresses.

## Prerequisite(s) #

A list of IP addresses that you identified as being malicious, suspicious and/or of interest.

## Microsoft Sentinel

MailItemsAccessed events are explicitely excluded since they need to be parsed differently. See the MailItemsAccessed queries page for these.

### Query #1 - Emails involved in Operations from flagged IPs (Item, raw format)

This query works for the following Operations, which uses the Item nested property:
- Create
- Send
- SendAs
- SendOnBehalf
- Update

```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| where OfficeWorkload == "Exchange"
| where Operation != "MailItemsAccessed"
| where isnotempty( Item)
| extend ParsedItem = parse_json(Item)
| extend ItemId = ParsedItem.Id
| extend ItemInternetMessageId = tostring(ParsedItem.InternetMessageId)
| extend ItemSubject = tostring(ParsedItem.Subject)
| extend ItemParentFolder = tostring(parse_json(ParsedItem.ParentFolder).Path)
```
### Query #2 - Emails involved in Operations from flagged IPs (Item, unique)

Summarized (unique InternetMessageId) version of Query #1.

IMPORTANT NOTE:

This query has a flaw because there are events that don’t have an InternetMessageId nor Subject, so it skew the results. Looks like the events are missing information. The only ID that exists for them is a unique, Microsoft-related id called “Id” under the Item column.

```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| where OfficeWorkload == "Exchange"
| where Operation != "MailItemsAccessed"
| where isnotempty( Item)
| extend ParsedItem = parse_json(Item)
| extend ItemId = ParsedItem.Id
| extend ItemInternetMessageId = tostring(ParsedItem.InternetMessageId)
| extend ItemSubject = tostring(ParsedItem.Subject)
| extend ItemParentFolder = tostring(parse_json(ParsedItem.ParentFolder).Path)
```
### Query #3 - Emails involved in Operations from flagged IPs (AffectedItems, raw format)

This query works for the following Operations, which uses the Item nested property:
- HardDelete
- Move
- MoveToDeletedItems
- SoftDelete

```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| where OfficeWorkload == "Exchange"
| where Operation != "MailItemsAccessed"
| where isnotempty( AffectedItems)
| extend SourceFolder = tostring(parse_json(Folder).Path)
| extend DestinationFolder = tostring(parse_json(DestFolder).Path)
| mv-expand todynamic(AffectedItems)
| extend AffectedItemInternetMessageId = tostring(parse_json(AffectedItems).InternetMessageId)
| extend AffectedItemSubject = tostring(parse_json(AffectedItems).Subject)
| extend AffectedItemParentFolderPath = tostring(parse_json(parse_json(AffectedItems).ParentFolder).Path)
```
### Query #4 - Emails involved in Operations from flagged IPs (AffectedItems, unique)

Summarized (unique InternetMessageId) version of Query #3.

IMPORTANT NOTE:

This query has a flaw because there are events that don’t have an InternetMessageId nor Subject, so it skew the results. Looks like the events are missing information. The only ID that exists for them is a unique, Microsoft-related id called “Id” under the Item column.

```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1"
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| where OfficeWorkload == "Exchange"
| where isnotempty( AffectedItems)
| extend SourceFolder = tostring(parse_json(Folder).Path)
| extend DestinationFolder = tostring(parse_json(DestFolder).Path)
| mv-expand todynamic(AffectedItems)
| extend AffectedItemInternetMessageId = tostring(parse_json(AffectedItems).InternetMessageId)
| extend AffectedItemSubject = tostring(parse_json(AffectedItems).Subject)
| extend AffectedItemParentFolderPath = tostring(parse_json(parse_json(AffectedItems).ParentFolder).Path)
| summarize ["Operations"]=make_set(Operation),
            ["Number of Operations"]=dcount(Operation),
            ["SourceFolders"]=make_set(SourceFolder),
            ["Number of SourceFolders"]=dcount(SourceFolder),
            ["DestinationFolders"]=make_set(DestinationFolder),
            ["Number of DestinationFolders"]=dcount(DestinationFolder),
            ["Subjects"]=make_set(AffectedItemSubject),
            ["Number of Subjects"]=dcount(AffectedItemSubject)
            by AffectedItemInternetMessageId
```
