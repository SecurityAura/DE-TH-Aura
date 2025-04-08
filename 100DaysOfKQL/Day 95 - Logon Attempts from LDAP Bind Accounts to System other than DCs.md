# *Logon Attempts from LDAP Bind Accounts to System other than DCs*

## Query Information

This query return events where a LDAP Bind account attempts to authenticate to an endpoint other than a DC.

##

#### Description

This query return events where a LDAP Bind account attempts to authenticate to an endpoint other than a DC (Domain Controller).

In the business, LDAP Bind accounts are typically (read: should be) read-only only accounts that allow a system (e.g.: firewall) to connect to a LDAP directory (read: Active Directory) to retrieve certain information that system requires.

For instance, if you configure SSL-VPN on a firewall with Active Directory authentication and User Group, you'll need a LDAP Bind account that can read whether users that tries to authenticate to the SSL-VPN are member of that defined group and therefore, allowed to VPN in.

Therefore, authentication from these accounts should always come from the systems they're configured on. Not only that, but they should only interact with DCs, the LDAP "directories" and not any other system. Since these are often configured on edge devices which can get compromised and therefore, their credentials dumped (whatever do you mean), they may be amongst the first accounts a threat actor has access to. Which means it ends up being common for them to try to authenticate with that account on multiple systems on the network to see what kind of access it has. And that's exactly how you can catch them.

Note: These queries requires you to know/identify two (2) things: Domain Controllers and LDAP Bind accounts. There are multiple ways to go about it, which I leave up to you. The queries below have two distinct examples of doing so.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query
- Microsoft Defender for Identity (MDI) - Coming soon

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
// There are multiple ways to dynamically get a list of Domain Controllers. The easiest way is to get them tagged in MDE and use them as a filter.
// Otherwise, you can just be lazy, define them in a dynamic variable and use it
let DomainControllers = dynamic([
    "DC1.company.local",
    "DC2.company.local"
]);
DeviceLogonEvents
// Similar to the DCs, there are multiple ways to go about grabbing LDAP Bind accounts. The easiest one is if they fit a certain naming scheme (e.g.: LDAP_FW, LDAP_WAF, LDAP_PRINTER, etc.)
// Replace the values below with ones that can be tokenized and fits your LDAP Bind accounts naming scheme. Otherwise, define them in a dynamic variable, like the DCs
| where AccountName has_any ("ldap", "bind")
| where DeviceName !in~ (DomainControllers)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
// There are multiple ways to dynamically get a list of Domain Controllers. The easiest way is to get them tagged in MDE and use them as a filter.
// Otherwise, you can just be lazy, define them in a dynamic variable and use it
let DomainControllers = dynamic([
    "DC1.company.local",
    "DC2.company.local"
]);
DeviceLogonEvents
// Similar to the DCs, there are multiple ways to go about grabbing LDAP Bind accounts. The easiest one is if they fit a certain naming scheme (e.g.: LDAP_FW, LDAP_WAF, LDAP_PRINTER, etc.)
// Replace the values below with ones that can be tokenized and fits your LDAP Bind accounts naming scheme. Otherwise, define them in a dynamic variable, like the DCs
| where AccountName has_any ("ldap", "bind")
| where DeviceName !in~ (DomainControllers)
```
