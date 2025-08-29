# *ExternalData - Cert Central, CertReport*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/17 | Initial version |
| 2025/08/24 | Added the wide DeviceFileCertificateInfo detection/hunt |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1553.002 | Subvert Trust Controls: Code Signing | https://attack.mitre.org/techniques/T1553/002/ |

#### Description

This query looks up files involved in DeviceProcessEvents, DeviceFileEvents or DeviceImageLoadEvents from a user's Downloads folder, or a subfolder in %APPDATA% or %LOCALAPPDATA% against the Cert Central/CertReport DB CSV export.

The goal of this query is to identify processes or files that are signed with certs present in Cert Central. The match is made on the Signer field, because multiple certificates can be assigned to a Signer, but not all of them will be in CertReport (e.g.: they haven't been reported yet).

The CertSerialMatchesCertReport column, with a value of TRUE or FALSE, will return whether the serial of the certificate in DeviceFileCertificateInfo matches the one in CertReport. If this returns TRUE, it means that the cert has been reported in CertReport and therefore, there are high chances that this file is malicious. If it returns FALSE, it means that there's only been a match on the Signer (e.g.: BLACK INDIGO LTD) but the serial from the file in MDE didn't match one in CertReport. At this point, you should investigate the file further to see if it's malicious or not. If it is, it may be signed with a new certificate that isn't in CertReport yet.

If you want to use these queries as an accurate detection rule, you should add a condition for the CertSerialMatchesCertReport column to TRUE. Otherwise, you can use it for hunting. You can still use it as a detection rule if you're OK in manually reviewing files that gets flagged whose cert does not match the one in CertReport.

Since "matches regex" is used to identify files at certain paths, depending on the size of the data you're querying, it may timeout and/or return incomplete result. Therefore, you may want to run it multiple batches, targeting specific tables and/or FolderPath each time.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://x.com/SquiblydooBlog/status/1934975511156941247
- https://certcentral.org/

### Queries Overview ###

- Defender for Endpoint (MDE) - 5 queries

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceImageLoadEvents, DeviceFileEvents (ALL-IN-ONE QUERY) ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
union DeviceProcessEvents, DeviceImageLoadEvents, DeviceFileEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
DeviceProcessEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceImageLoadEvents ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
DeviceImageLoadEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
DeviceFileEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceFileCertificateInfo, DeviceProcessEvents, DeviceEvents
```KQL
let CertReport = (externaldata(CRHash: string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
    [@"https://certcentral.org/api/download_csv"]
    with (format=csv))
    | extend CRSerial = tolower(CRSerial);
let PresentCertificateSigners = materialize(
    DeviceFileCertificateInfo
    | distinct Signer, CertificateSerialNumber
    | join CertReport on $left.Signer == $right.CRSigner
    | extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
    // If you only want to match on Signer name, which is more suited for hunting potential new certificate rather than detecting files with known Signers in Cert Central, change the value to FALSE.
    | where CertSerialMatchesCertReport == "TRUE"
    | distinct Signer);
let Hashes = materialize (
    DeviceFileCertificateInfo
    | where Signer in (PresentCertificateSigners)
    | distinct SHA1);
let Files = (
    union DeviceProcessEvents, DeviceFileEvents
    | where SHA1 in (Hashes)
    | join kind=inner DeviceFileCertificateInfo on SHA1);
Files
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceImageLoadEvents, DeviceFileEvents (ALL-IN-ONE QUERY) ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
union DeviceProcessEvents, DeviceImageLoadEvents, DeviceFileEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
DeviceProcessEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceImageLoadEvents ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
DeviceImageLoadEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
let CertReport = (externaldata(CRHash:string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
[@"https://certcentral.org/api/download_csv"]
with (format=csv))
| extend CRSerial = tolower(CRSerial);
DeviceFileEvents
| where FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Downloads\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Local\\[^\\]+\\.*(exe|dll|msi|msix)$"
   or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\.*(exe|dll|msi|msix)$"
| where FolderPath !has "\\AppData\\Local\\Temp\\"
| distinct DeviceName, SHA1, FolderPath
| join DeviceFileCertificateInfo on DeviceName, SHA1
| join CertReport on $left.Signer == $right.CRSigner
| extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
| project-reorder DeviceName, SHA1, FolderPath, CertSerialMatchesCertReport, CRSerial, CertificateSerialNumber, CRSigner, Signer, SignerHash, CRThumbprint
```
### Defender for Endpoint (MDE) via DeviceFileCertificateInfo, DeviceProcessEvents, DeviceEvents
```KQL
let CertReport = (externaldata(CRHash: string, CRMalware: string, CRSigner: string, CRIssuerShort: string, CRIssuer: string, CRSerial: string, CRThumbprint: string, CRValidFrom: datetime, CRValidTo: datetime, CRCountry: string, CRState: string, CRLocality: string, CREmail: string, CRRDNSerialNumber: string)
    [@"https://certcentral.org/api/download_csv"]
    with (format=csv))
    | extend CRSerial = tolower(CRSerial);
let PresentCertificateSigners = materialize(
    DeviceFileCertificateInfo
    | distinct Signer, CertificateSerialNumber
    | join CertReport on $left.Signer == $right.CRSigner
    | extend CertSerialMatchesCertReport = iif( CertificateSerialNumber == CRSerial, "TRUE", "FALSE")
    // If you only want to match on Signer name, which is more suited for hunting potential new certificate rather than detecting files with known Signers in Cert Central, change the value to FALSE.
    | where CertSerialMatchesCertReport == "TRUE"
    | distinct Signer);
let Hashes = materialize (
    DeviceFileCertificateInfo
    | where Signer in (PresentCertificateSigners)
    | distinct SHA1);
let Files = (
    union DeviceProcessEvents, DeviceFileEvents
    | where SHA1 in (Hashes)
    | join kind=inner DeviceFileCertificateInfo on SHA1);
Files
```
