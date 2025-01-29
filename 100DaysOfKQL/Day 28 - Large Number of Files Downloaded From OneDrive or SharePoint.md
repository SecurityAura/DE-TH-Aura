# *Large Number of Files Downloaded From OneDrive or SharePoint*

## Query Information

These queries returns events where a large number of files would have been downloaded from OneDrive or SharePoint.

##

#### Description

These queries returns events where a large number of files, based on the OfficeObjectId or FileSize, would have been downloaded from OneDrive or SharePoint. When files are downloaded from OneDrive and/or SharePoint, we're interested in how many unique files (OfficeObjectId) were downloaded in an set (X) amount of time. While at the endpoint level, we're interested in the FileSize of the resulting ZIP archive as a hint of how many files it could have (even though the FileSize can always be skewed because of large files with a low compression ratio).

In terms of data exfil, an easy way for threat actors (or even insiders) to collect files is simply to download them from the OneDrive or SharePoint web interface directly. When multiple files, or even folders, are downloaded from OneDrive/SharePoint online you will have:

- At the Office level: A specific user agent, which is OneDriveMpc-Transform_Zip/1.0
- At the endpoint level: An archive named OneDrive_yyyy_MM_dd.zip will be created, normally in the user's Downloads folder

You therefore have two (2) ways to investigate large/bulk downloads of files from OneDrive/SharePoint. The disadvantage with the 2nd query, which is based on DeviceFileEvents, is that technically, you don't know always knows if these are your organization files, as it could be an archive that was generated from files/folders downloaded from another organization's OneDrive and/or SharePoint. The FileOriginUrl and FileOriginReferrerUrl columns of the DeviceFileEvents table will sometimes give insight on the original URL, which may contain the OneDrive/SharePoint site the .zip archive was generated/downloaded from.

These queries are more suited for hunting, rather than pure detection. In terms of detection, you would need to add additional filters and/or correlation. For instance, at the Office level, see if these files are downloaded to an unmanaged device (IsManagedDevice) or do enrichment on the IP address to help assess the legitimacy of the action.

At the endpoint level, you could correlate further to see if these archives are moved to an external storage media (e.g.: USB Flash Drive) or see if the device access any kind of file sharing website (e.g.: Mega, PCloud, etc.) shortly after the creation of the archive.

PS: Don't sleep on the FileOriginUrl and FileOriginReferrerUrl in the DeviceFileEvents. You may find interesting things, even for situations you would not expect. A bit of teasing for a next #100DaysOfKQL query maybe?

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://www.varonis.com/blog/sidestepping-detection-while-exfiltrating-sharepoint-data

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query
- Microsoft Sentinel - OfficeActivity (via Microsoft 365) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
// You can remove the FolderPath regex if you want events where the OneDrive zip could've been saved elsewhere on the system.
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
| where FileName startswith "OneDrive_"
| where FileName endswith ".zip"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
// You can remove the FolderPath regex if you want events where the OneDrive zip could've been saved elsewhere on the system.
| where FolderPath matches regex @"(?i)\\Users\\[^\\]+\\Downloads\\(.*)?"
| where FileName startswith "OneDrive_"
| where FileName endswith ".zip"
```
### Microsoft 365 via OfficeActivity ###
```KQL
// Threshold based query, where you need to adjust the Timespan for the bin() and number of unique OfficeObjectIds to fit your needs
let Timespan = 10m;
let DistinctOfficeObjectIdThreshold = 1000;
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload in ("OneDrive","SharePoint")
| where Operation == "FileDownloaded"
| where UserAgent has "OneDriveMpc-Transform_Zip"
| summarize ["OfficeObjectIds"]=make_set(OfficeObjectId),
            ["OfficeObjectIdsCount"]=dcount(OfficeObjectId),
            ["OfficeWorkloads"]=make_set(OfficeWorkload),
            ["OfficeWorkloadsCount"]=dcount(OfficeWorkload)
            by UserId, bin(TimeGenerated, Timespan)
| where OfficeObjectIdsCount > DistinctOfficeObjectIdThreshold
```
