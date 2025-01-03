# *Split or Part Archive Files*

## Query Information

This query look for file events where split and/or part file archives are involved.

##

#### Description

When it comes to data exfiltration, many threat actors may rely on archiving utilities to collect/stage the data they want to exfiltrate beforehand. For instance, put in a RAR or 7z archive all the Office and PDF related files from a network share.

With applications such as WinRAR and 7-Zip, you also have the option to create split or part archives. Basically, instead of putting inside a single archive a folder with around 10 GB of data, you can break it down in smaller archives of maximum 1 GB each. Depending on which application is used, the split/part archives created have a distinctive naming scheme:

- WinRAR - Ends with partX.rar (e.g.: Finances.part1.rar, Finances.part11.rar, Finances.part111.rar, etc.)
- 7-Zip - Ends with 7z.X (e.g.: Finances.7z.001, Finances.7z.011, Finances.7z.111, etc.)

Since we know how these files are named, we can then look for them via Defender for Endpoint (MDE) using the DeviceFileEvents table.

Note: Split archives can be created using other format/extensions. For instance, you can also create split archives in a ZIP format using 7-Zip. The query below only showcases the RAR and 7z extensions, which are the most popular.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FileName matches regex @'(?i)\.part[0-9]{1,}\.rar'
    or FileName matches regex @'(?i)\.7z\.[0-9]{1,}'
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FileName matches regex @'(?i)\.part[0-9]{1,}\.rar'
    or FileName matches regex @'(?i)\.7z\.[0-9]{1,}'
```
