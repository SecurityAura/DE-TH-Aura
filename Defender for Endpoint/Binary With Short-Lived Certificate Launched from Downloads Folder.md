# *Binary With Short-Lived Certificate Launched from Downloads Folder*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/10/05 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.002 | User Execution: Malicious File | https://attack.mitre.org/techniques/T1204/002/ |

#### Description

This query looks for the execution of processes within a user's Downloads folder, where the binary is signed with a short-lived certificate (7 days or else).

The idea for this query comes from a recent OysterLoader/Broomstick campaign using short-lived certificates and masquerading as installers for known/popular software (such as Microsoft Teams).

This query is probably better suited for hunting, rather than detection. However, you could turn it in a detection by leveraging the GlobalPrevalence value and look for results with a low global prevalence (e.g.: under 100).

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s) ####

- https://x.com/SquiblydooBlog/status/1971575773904740437
- https://conscia.com/blog/from-seo-poisoning-to-malware-deployment-malvertising-campaign-uncovered/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceFileCertificateInfo ###
```KQL
// Adjust the certificate time-span threshold as needed (can be 4 to get certs valid for 3 days for instance)
let CertTimeDifferenceThreshold = 8;
DeviceProcessEvents
| where FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Downloads\\(.*)?"
| distinct DeviceName, FolderPath, SHA1
| join DeviceFileCertificateInfo on DeviceName, SHA1
| where Signer != "Microsoft Corporation"
| extend CertTimeDifference = datetime_diff('day', CertificateExpirationTime, CertificateCreationTime)
| where CertTimeDifference < CertTimeDifferenceThreshold
| invoke FileProfile("SHA1", 1000)
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceFileCertificateInfo ###
```KQL
// DISCLAIMER: Since we use FileProfile(), this query does not work in Microsoft Sentinel. However, unless you actually want to use it as a detection (as mentioned above), you don't need to rely on it for hunting purposes.
// Adjust the certificate time-span threshold as needed (can be 4 to get certs valid for 3 days for instance)
let CertTimeDifferenceThreshold = 8;
DeviceProcessEvents
| where FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\Downloads\\(.*)?"
| distinct DeviceName, FolderPath, SHA1
| join DeviceFileCertificateInfo on DeviceName, SHA1
| where Signer != "Microsoft Corporation"
| extend CertTimeDifference = datetime_diff('day', CertificateExpirationTime, CertificateCreationTime)
| where CertTimeDifference < CertTimeDifferenceThreshold
```
