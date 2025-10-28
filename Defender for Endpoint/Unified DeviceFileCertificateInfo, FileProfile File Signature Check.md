# *Unified DeviceFileCertificateInfo, FileProfile File Signature Check*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/10/27 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1553.002 | Subvert Trust Controls: Code Signing | https://attack.mitre.org/techniques/T1553/002/ |

#### Description

This queries unifies the lookup of a file signature (per it's SHA1) in both DeviceFileCertificateInfo and FileProfile.

The issue with DeviceFileCertificateInfo is that it's not always populated with records which would indicate if a file is a signed or not:

- Per current observations, this table ONLY contains records for SIGNED files. There is no "IsSigned == false", only "IsSigned == true"
- Therefore, depending on the join you use (e.g.: inner), the absence of results in that join does not MEAN that the hash it looked up is not signed
- It is possible that the timerange you're using for the lookup does not cover the period where an entry for that hash exists in the table
- And sadly, it's possible that this table simply never logged a record/entry for that file, EVEN if it's signed

Therefore, a fallback that can be used is to combine this with FileProfile(), which does return information about a file and whether or not it's signed.

The goal of this query, through the UnifiedCertificateStatus, is to give you a clear output as to whether or not a file is: Signed, Unsigned and if Signed, if it's Trusted or Untrusted. Since FileProfile() is prone to errors and a limit can also be hit (can't handle more than 1,000 lookups per query), the query accounts for this as well and will display an Error message/value in the column instead, should it happen.

While this query is shown with DeviceProcessEvents, you can use it with any table, as long as you define that logic between the two (2) commented lines. If you want to lookup an InitiatingProcessSHA1 instead, do not forget to adjust your key values in the join.

Since we're using FileProfile(), this query ONLY works in the Microsoft Defender XDR console.

Mehmet Ergene (@Cyb3rMonk on Twitter/X) also deserves credits for the idea, rationale behind this query.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
// INSERT YOUR FILTERING LOGIC IN THIS BLOCK
| where FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\Local\\(.*?)"
// END OF YOUR FILTERING LOGIC
// Change SHA1 for InitiatingProcessSHA1 should you be using that column instead.
| where isnotempty( SHA1)
| distinct DeviceName, FolderPath, SHA1
| join kind=leftouter DeviceFileCertificateInfo on SHA1
// Comment the previous line and uncomment the following one if you're using InitiatingProcessSHA1 instead
//| join kind=leftouter DeviceFileCertificateInfo on $left.InitiatingProcessSHA1 == $right.SHA1
// Change SHA1 for InitiatingProcessSHA1 should you be using that column instead.
| invoke FileProfile("SHA1",1000)
| extend CertificateInfoSource = case(
                                    isnotempty( IsSigned) 
                                        and isnotempty( ProfileAvailability), dynamic(["DeviceFileCertificateInfo,FileProfile"]),
                                    isnotempty( IsSigned), dynamic(["DeviceFileCertificateInfo"]),
                                    dynamic(["FileProfile"]))
| extend UnifiedCertificateStatus = case(
                                    CertificateInfoSource has_any ("DeviceFileCertificateInfo")
                                        and IsTrusted == 0, dynamic(["Signed","Trusted"]),
                                    CertificateInfoSource has_any ("DeviceFileCertificateInfo")
                                        and IsTrusted == 1, dynamic(["Signed","Untrusted"]),
                                    SignatureState == "SignedValid", dynamic(["Signed","Trusted"]),
                                    SignatureState == "SignedInvalid", dynamic(["Signed","Untrusted"]),
                                    SignatureState == "Unsigned", dynamic(["Unsigned"]),
                                    SignatureState == "Error", dynamic(["Error"]),
                                    dynamic(["General Error, FileProfile may have crashed"]))
| project-reorder TimeGenerated, DeviceName, FolderPath, SHA1, CertificateInfoSource, UnifiedCertificateStatus
```
