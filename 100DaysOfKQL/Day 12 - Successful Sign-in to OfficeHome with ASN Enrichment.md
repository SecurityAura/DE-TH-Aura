# *Script Execution From User's Downloads Folder*

## Query Information

This query returns all successful sign-ins in Entra ID for the OfficeHome application with ASN enrichment on the IP the sign-in came from.

##

#### Description

This query returns all successful, whether the access was granted or not, sign-ins in Entra ID for the OfficeHome (portal.office.com) application with ASN enrichment on the IP the sign-in came from. The ASN enrichment is done through GypTheCat[.]com awesome Kusto ASN Table. Once again, thank you to Matt Zorich (@reprise99) for showing me that site and resource!

https://firewalliplists.gypthecat.com/kusto-tables/kusto-asn-table/

This is something you'll often see in "Attacker-in-the-middle" phishing, where a successful sign-in will be generated from an IP associated with a bad and/or mostly server hosting/colocation ASN and the associated app will be OfficeHome. See the reference(s) below.

That specific behavior, while it can be changed, is still quite common/popular and therefore, can be easily detectable and/or hunted for in most environments (small, or large).

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/Adversary-in-the-Middle.md#hunting-of-officehome-application-sign-ins-by-dart-team-query
- https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
- https://jeffreyappel.nl/aitm-mfa-phishing-attacks-in-combination-with-new-microsoft-protections-2023-edt/

### Queries Overview ###

- Microsoft Sentinel - Signin (via Microsoft Entra ID)

## Microsoft Sentinel ##
### Microsoft Entra ID via SigninLogs ###
```KQL
let CIDRASN = (
    externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string, CIDRSource:string)
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
    with (ignoreFirstRecord=true)
);
// Taken from Matt Zorich (@reprise99) awesome website: https://learnsentinel.blog/2021/08/30/azure-sentinel-and-the-story-of-a-very-persistent-attacker/
let SuccessCodes = dynamic([0, 50055, 50057, 50155, 50105, 50133, 50005, 50076, 50079, 50173, 50158, 50072, 50074, 53003, 53000, 53001, 50129]);
SigninLogs
| where AppDisplayName == "OfficeHome"
| where ResultType in (SuccessCodes)
| evaluate ipv4_lookup(CIDRASN, IPAddress, CIDR, return_unmatched=true)
```
