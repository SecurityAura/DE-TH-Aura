# *Successful Sign-in to Target Accounts From Non-TrustedNamedLocation*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/26 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

This query returns events where successful sign-ins (per Matt Zorich (@reprise99) awesome list of ResultTypes) to target account(s) (user-defined) are observed from non-trusted named locations.

Named Locations can be defined in Conditional Access as countries or IP ranges to mark them as trusted if needed in certain Conditional Access Policies. For instance, you may want a breakglass account to only be used from an IP range which is associated with your primary datacenter site.

Or you may want to only allow "service" accounts* (e.g.: UPN starting with "svc") to sign-in from your datacenter IP ranges (primary, secondary, DR, etc.). Which is exactly the use case I had when I came up with this query earlier this week. See if any "service" accounts were used outside of Trusted Named Locations, which any of the company's sites around the world and more-so, if they were accessed programmatically based on the user-agent (such as Python).  

Another use case would be to look for high-privilege accounts (e.g.: accounts used to manage Azure/Entra with high-privileges/roles) that are succesfully signed-in from non trusted named locations which could be company offices and/or networks.

What you can use this query for here really is only limited by what you want/need to look for, depending on your use case(s).

*The term "service" account is used lightly here, as some organizations are still making the same mistakes today in Azure/Entra ID as they did on-prems: create normal user accounts and using them for "services"-like purposes.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network

### Queries Overview ###

- Microsoft Sentinel - Signin (via Microsoft Entra ID) - 1 query

## Microsoft Sentinel ##
### Microsoft Entra ID via SigninLogs ###
```KQL
let UPNs = dynamic([
    "UPN1",
    "UPN2"
]);
// Taken from Matt Zorich (@reprise99) awesome website: https://learnsentinel.blog/2021/08/30/azure-sentinel-and-the-story-of-a-very-persistent-attacker/
let SuccessCodes = dynamic([0, 50055, 50057, 50155, 50105, 50133, 50005, 50076, 50079, 50173, 50158, 50072, 50074, 53003, 53000, 53001, 50129]);
SigninLogs
| where UserPrincipalName in~ (UPNs)
// Alternatively, you can target UPns based on naming scheme if you want. For instance, if their UPN starts with "svc". If you use that kind of filter, comment the line above, and uncomment the one below.
//| where UserPrincipalName startswith "svc"
| where ResultType in (SuccessCodes)
// If you want to filter on specific User-Agents, uncomment the filter below and add the ones you're looking for. 
//| where UserAgent has_any ("python","powershell")
| where NetworkLocationDetails !has "trustedNamedLocation"
```
