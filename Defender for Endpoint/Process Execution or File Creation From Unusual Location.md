# *Process Execution or File Creation From Unusual Location*

## Query Information

One of the most effective detection rule and/or threat hunt you can have on any intrusion incident, ransomware or not. A lot of threat actors will drop files (executables or not, e.g.: script output) in publicly accessible folders where files should rarely get written and/or processes rarely executed out of. To not say never in most cases.

This query looks for any files that would be created in these locations and/or processes executing out of these.

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

Despite all my research and effort, it does not seem like there's a specific TTP for this.

#### Description

This rule detects when a file gets created and/or process executed out of the following folders:

- C:\ drive - Root
- C:\Intel - Recursive
- C:\PerfLogs - Recursive
- C:\ProgramData - Root
- C:\Program Files - Root
- C:\Program Files (x86) - Root
- C:\Users\Public - Recursive
- C:\Users\\* - Root
- C:\Users\\*\AppData - Root
- C:\Users\\*\AppData\Local - Root
- C:\Users\\*\AppData\Roaming - Root
- C:\Users\\*\Favorites - Recursive
- C:\Users\\*\Music - Recursive
- C:\Users\\*\Pictures - Recursive
- C:\Users\\*\Videos - Recursive

A lot of threat actors will end up dropping their binaries and/or files at the root of C:\ProgramData and/or C:\Users\Public. So if you have to prioritize locations, pick these two.

Other locations could be added, but be wary of false positives (such as C:\Users\*\Documents).

#### Risk

A threat actor is staging his tools and/or files in one of these directories.

False positives can occur, but should be easily spottable. For instance, a specific Windows Update back in the day would drop the install files at the root of the C:\ drive. LogMeIn Rescue drops .bat files in %LocalAppData%, etc.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### References
- https://twitter.com/SecurityAura/status/1839489644020318342

## Defender XDR - Query #1 - DeviceProcessEvents
```KQL
DeviceProcessEvents
| where FolderPath matches regex @'(?i)C\:\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Intel\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\PerfLogs\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\ProgramData\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\sFiles\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\sFiles\s\(x86\)\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\Public\\(.*)?' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\[^\\]+$'
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Favorites\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Music\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Pictures\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Videos\\(.*)?"
```
## Sentinel - Query #1 - DeviceProcessEvents
```KQL
DeviceProcessEvents
| where FolderPath matches regex @'(?i)C\:\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Intel\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\PerfLogs\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\ProgramData\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\ Files\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\ Files\ \(x86\)\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\Public\\(.*)?' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\[^\\]+$'
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Favorites\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Music\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Pictures\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Videos\\(.*)?"
```
## Defender XDR - Query #2 - DeviceFileEvents
```KQL
DeviceFileEvents
| where FolderPath matches regex @'(?i)C\:\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Intel\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\PerfLogs\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\ProgramData\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\ Files\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\ Files\ \(x86\)\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\Public\\(.*)?' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\[^\\]+$'
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Favorites\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Music\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Pictures\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Videos\\(.*)?"
```
## Sentinel - Query #2 - DeviceFileEvents
```KQL
DeviceFileEvents
| where FolderPath matches regex @'(?i)C\:\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Intel\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\PerfLogs\\(.*)?'
    or FolderPath matches regex @'(?i)C\:\\ProgramData\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\ Files\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Program\ Files\ \(x86\)\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\Public\\(.*)?' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\[^\\]+$' 
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+$'
    or FolderPath matches regex @'(?i)C\:\\Users\\[^\\]+\\[^\\]+$'
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Favorites\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Music\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Pictures\\(.*)?"
    or FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Videos\\(.*)?"
```
