# *OfficeActivity - OfficeWorkload and Operations Summary from Flagged IPs*

## Description

The queries below can be used to obtain a summary of OfficeActivity Operations and their associated OfficeWorkload from the OfficeActivity table in Microsoft Sentinel.

## Prerequisite(s) #

A list of IP addresses that you identified as being malicious, suspicious and/or of interest.

## Microsoft Sentinel
### Query #1 - Operations and RecordTypes summarization by OfficeWorkload
```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| summarize count(),
            ["Operations"]=make_set(Operation),
            ["Number of Operations"]=dcount(Operation),
            ["RecordTypes"]=make_set(RecordType),
            ["Number of RecordTypes"]=dcount(RecordType)
            by OfficeWorkload
```
### Query #2 - Count of events per OfficeWorkload, Operation and UserId
```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where ClientIP has_any (FlaggedIPs)
  or Client_IPAddress has_any (FlaggedIPs)
  or ActorIpAddress has_any (FlaggedIPs)
| summarize count() by OfficeWorkload, Operation, UserId
```
