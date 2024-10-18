# *OfficeActivity - SharePoint & OneDrive Accessed Files Breakdown.md*

## Description

The queries below can be used to obtain information about SharePoint/OneDrive OfficeWorkload events from flagged IP addresses.

It'll give you a list of unique files, based on their path, that were involved in operations from the flagged IP addresses. You should assume that, depending on the Operation, or if you don't want to take any chance, all of them, that the content of every file listed in the results is not private anymore and has been accessed by an unauthorized third-party.

## Prerequisite(s) #

A list of IP addresses that you identified as being malicious, suspicious and/or of interest.

## Microsoft Sentinel
### Query - SharePoint/OneDrive files involved in Operations from flagged IPs.
```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
OfficeActivity
| where OfficeWorkload in~ ("SharePoint","OneDrive")
| summarize ["Operations"]=make_set(Operation),
            ["Number of Operations"]=dcount(Operation),
            ["SiteURLs"]=make_set(Site_Url),
            ["Number of SiteURLs"]=dcount(Site_Url),
            ["SourceFileNames"]=make_set(SourceFileName),
            ["Number of SourceFileNames"]=dcount(SourceFileName)
            by OfficeObjectId, UserId
```
