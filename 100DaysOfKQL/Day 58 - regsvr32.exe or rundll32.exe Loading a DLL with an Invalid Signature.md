# *Non-Sucking Service Manager (nssm) Usage*

## Query Information

This query returns events where rundll32.exe or regsvr32.exe loads a DLL with an invalid signature.

##

#### Description

This query returns events where rundll32.exe or regsvr32.exe loads a file with an invalid signature, per Defender for Endpoint (MDE) FileProfile().

Loading DLLs through regsvr32.exe or rundll32.exe is a threat actor's (or malware) favorite. They are LOLBAS, they hide in plain sight, you just have to pass them an innocuous filename so from a ProcessCommandLine perspective, it doesn't attract attention. Same thing with the entry points which can be the same as known/benign ones (see the References section for an example).

It does not mean that these files are always signed, or that their signature will remain valid forever (#ImposeCost and Squiblidoo's certReport amirite?). In Defender for Endpoint, you can use the FileProfile() function to get interesting information about a file, namely:

- It's signature state
- Whether the certificate is valid or not

Therefore, it is possible to single out files loaded by rundll32.exe or regsvr32.exe, pass them through FileProfile() and from there, get files whose signature or certificate are not valid.

As with every query that uses FileProfile(), be mindful of the number of hashes you're going to pass through it since it has a 1,000 lookup limit per query.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

###  References ###

- https://cloud.google.com/blog/topics/threat-intelligence/unc2596-cuba-ransomware/
- https://github.com/Squiblydoo/certReport
- https://medium.com/falconforce/microsoft-defender-for-endpoint-internals-0x03-mde-telemetry-unreliability-and-log-augmentation-ec6e7e5f406f (awareness on the limitations of the DeviceImageLoadEvents table)

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceImageLoadEvents ###
```KQL
// You can define a GlobalPrefalence threshold to only get back files that aren't prevalent globally per Microsoft
// Otherwise, you can simply drop the last filter altogether to get all the results
let GlobalPrevalenceThreshold = 500
let UnsignedLowPrevFiles = (DeviceImageLoadEvents
| where InitiatingProcessFileName in~ ("regsvr32.exe", "rundll32.exe")
| where isnotempty( SHA1)
| distinct SHA1
| invoke FileProfile("SHA1",1000)
| where IsCertificateValid != 1
    or SignatureState != "SignedValid"
| where GlobalPrevalence < GlobalPrevalenceThreshold);
DeviceImageLoadEvents
| where InitiatingProcessFileName in~ ("regsvr32.exe", "rundll32.exe")
| join UnsignedLowPrevFiles on SHA1
```
