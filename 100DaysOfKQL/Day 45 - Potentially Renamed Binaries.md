# *Potentially Renamed Binaries*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/14 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1036 | Masquerading | https://attack.mitre.org/techniques/T1036/ |

#### Description

*CREDIT IS GIVEN WHERE CREDIT IS DUE*

I came up with this query some time ago already and at that time, I ended up discovering the set_has_element() function in KQL. Like with every function I've never used before, I browse various KQL repos to get an idea of how to use them. The reason I do this is because the Microsoft Learn docs content for these functions is often very sparse and not that helpful. So it's better for me to just find an actual example of the function used for security-related queries.

This being said, I ended up finding the following query in FalconForce's FalconFriday Github repo. Which you should definitely go star and follow them on all their socials, they are just amazing:

https://github.com/FalconForceTeam/FalconFriday/blob/355de126c6cc707d1a62970a5989b06c8cd686b9/0xFF-0080-Parent_Child_Mismatch_Common_Windows_Process-Win.md

Therefore, the query shown here is very similar to what they have because I used their as a model for what I wanted to accomplish. Kudos to them!

/end

This query returns events where a binary that was executed is potentially renamed, per a datatable that is prepopulated with the right, expected values to identify that binary.

It is not uncommon for threat actors and/or malware to rename legitimate binaries in order to fly under the radar. They may even move them out (well, copy them) of their usual location and then call them from that new location. The use case we're targeting here, is a very simple one where a threat actor executed a renamed copy of rclone.exe on an system. Since it has just been renamed, all the information (metadata) related to the file, and captured by Defender for Endpoint (MDE) will show up in the telemetry. And we can then do something that basically amounts:

If process has FileInfo of rclone, but EXE is not named rclone.exe, BAD!

To do so, we define a datatable with the expected "pair" of values we're expecting, basically: a file named rclone.exe, with a OriginalFileName that has the string "rclone". We then look through DeviceProcessEvents for that kind of mismatch and if found, return the results.

You can add any "pair" of expected values in the datatable, which makes it useful if you want to monitor for specific binaries that would've been renamed: rclone, 7-Zip, WinRAR being some of the most common and interesting ones.

To make this query less resource intensive, you could add a filter first that only looks for processes where the ProcessVersionInfoOriginalFileName has any of the strings you're looking for (e.g.: rclone).

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let PotentiallyRenamedBinaries = datatable(ProcessVersionInfoOriginalFileNameLower: string,ExpectedFileName: dynamic)
[
    "rclone.exe",dynamic(["rclone"])
];
DeviceProcessEvents
| extend FileNameLower = tolower(FileName)
| extend ProcessVersionInfoOriginalFileNameLower = tolower(ProcessVersionInfoOriginalFileName)
| lookup kind=inner PotentiallyRenamedBinaries on ProcessVersionInfoOriginalFileNameLower
| where not(set_has_element(ExpectedFileName,FileNameLower))
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let PotentiallyRenamedBinaries = datatable(ProcessVersionInfoOriginalFileNameLower: string,ExpectedFileName: dynamic)
[
    "rclone.exe",dynamic(["rclone"])
];
DeviceProcessEvents
| extend FileNameLower = tolower(FileName)
| extend ProcessVersionInfoOriginalFileNameLower = tolower(ProcessVersionInfoOriginalFileName)
| lookup kind=inner PotentiallyRenamedBinaries on ProcessVersionInfoOriginalFileNameLower
| where not(set_has_element(ExpectedFileName,FileNameLower))
```
