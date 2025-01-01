# *Authentication From Suspicious WorkstationName*

## Query Information

This query looks for authentication events where the remote workstation name has a suspicious string in it.

##

#### Description

This query looks for authentication events where the remote workstation name could be a default Windows one, such as:

- DESKTOP-x
- LAPTOP-x
- WIN-x

When a threat actor connects to an environment through VDI (such as Citrix), VPN and/or via a compromised edge appliance (such as firewall), its workstation name (hostname or else) can be included in authentication events (such as 4624s and 4625s).

Therefore, actively detecting and/or seeking out authentication events where these strings are present can help in identifying potentially suspicious systems in the environment.

The caveat of this query is that, if the environment doesn't have a standardized naming convention (e.g.: default Windows names are used) and/or one that overlaps with the defined strings, there can be false positives. Therefore, adjust and/or fine-tune the queries accordingly.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query
- Defender for Identity (MDI) - 1 query
- Microsoft Sentinel (SecurityEvent) - 1 query

## Defender XDR ##
### Query 1 - Defender for Endpoint (MDE) via DeviceLogonEvents ###
```KQL
let SuspiciousWorkstationNameStrings = dynamic([
    "DESKTOP",
    "LAPTOP",
    "WIN"
]);
DeviceLogonEvents
| where RemoteDeviceName has_any (SuspiciousWorkstationNameStrings)
```
## Defender XDR ##
### Query 2 - Defender for Identity (MDI) via IdentityLogonEvents ###
```KQL
let SuspiciousWorkstationNameStrings = dynamic([
    "DESKTOP",
    "LAPTOP",
    "WIN"
]);
IdentityLogonEvents
| extend RemoteWorkstationName = tostring(parse_json(AdditionalFields).["FROM.DEVICE"])
| where RemoteWorkstationName has_any (SuspiciousWorkstationNameStrings)
```
## Microsoft Sentinel ##
### Query 1 - Defender for Endpoint (MDE) via DeviceLogonEvents ###
```KQL
let SuspiciousWorkstationNameStrings = dynamic([
    "DESKTOP",
    "LAPTOP",
    "WIN"
]);
DeviceLogonEvents
| where RemoteDeviceName has_any (SuspiciousWorkstationNameStrings)
```
### Query 2 - Defender for Identity (MDI) via IdentityLogonEvents ###
```KQL
let SuspiciousWorkstationNameStrings = dynamic([
    "DESKTOP",
    "LAPTOP",
    "WIN"
]);
IdentityLogonEvents
| extend RemoteWorkstationName = tostring(parse_json(AdditionalFields).["FROM.DEVICE"])
| where RemoteWorkstationName has_any (SuspiciousWorkstationNameStrings)
```
### Query 3 - Security Event ID 4624 (Successful Logon) and 4625 (Failed Logon) ###
```KQL
let SuspiciousWorkstationNameStrings = dynamic([
    "DESKTOP",
    "LAPTOP",
    "WIN"
]);
SecurityEvent
| where EventID in ("4624","4625")
| where WorkstationName has_any (SuspiciousWorkstationNameStrings)
```
