# *ngrok Usage*

## Query Information

This query returns events where ngrok was observed.

##

#### Description

This query returns events where ngrok was observed through various means.

ngrok is a legitimate reverse proxy tool that can be used to create secure tunnels and whose main purpose is basically to expose endpoints and applications so that they can be used externally. The way the threat actors use it however, is also to set up reverse tunnels so that they can then remotely connect to these internal endpoints externally. One of their common use case is to setup a ngrok agent on a compromised system and from the tunnel that has been set up, RDP into that system. Which is much more confortable to work with when you have access to a GUI at this point.

A lot of these reverse proxy tool/reverse tunnel tools exists (you can do the same with SSH and PLINK for instance), though ngrok remains one of the most popular ones. There are a few ways to detect ngrok usage on a system through Defender for Endpoint (MDE) telemetry, luckily for us.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://www.huntress.com/blog/abusing-ngrok-hackers-at-the-end-of-the-tunnel
- https://attack.mitre.org/software/S0508/
- https://news.sophos.com/en-us/2022/07/14/rapid-response-the-ngrok-incident-guide/

### Queries Overview ###

- Defender for Endpoint (MDE) - 4 queries
- Microsoft Sentinel (via SecurityEvent and Event) - 2 queries

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "ngrok.exe"
    or ProcessVersionInfoProductName has "ngrok"
    or ProcessVersionInfoFileDescription has "ngrok"
    or InitiatingProcessFileName =~ "ngrok.exe"
    or InitiatingProcessVersionInfoProductName has "ngrok"
    or InitiatingProcessVersionInfoFileDescription has "ngrok"
```
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "ngrok.exe"
    or InitiatingProcessVersionInfoProductName has "ngrok"
    or InitiatingProcessVersionInfoFileDescription has "ngrok"
    // There are many ngrok-related domains and URLs, but they all have the ngrok string in it and it's pretty unique
    or RemoteUrl has "ngrok"
```
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
// The default filename used for ngrok config file
| where FileName =~ "ngrok.conf"
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| where AdditionalFields.ServiceName has "ngrok"
    or FileName =~ "ngrok.exe"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "ngrok.exe"
    or ProcessVersionInfoProductName has "ngrok"
    or ProcessVersionInfoFileDescription has "ngrok"
    or InitiatingProcessFileName =~ "ngrok.exe"
    or InitiatingProcessVersionInfoProductName has "ngrok"
    or InitiatingProcessVersionInfoFileDescription has "ngrok"
```
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "ngrok.exe"
    or InitiatingProcessVersionInfoProductName has "ngrok"
    or InitiatingProcessVersionInfoFileDescription has "ngrok"
    // There are many ngrok-related domains and URLs, but they all have the ngrok string in it and it's pretty unique
    or RemoteUrl has "ngrok"
```
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
// The default filename used for ngrok config file
| where FileName =~ "ngrok.conf"
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
| where AdditionalFields.ServiceName has "ngrok"
    or FileName =~ "ngrok.exe"
```
### SecurityEvent ###
```KQL
SecurityEvent
| where EventID == 4697
| where ServiceName has "ngrok"
    or ServiceFileName has "ngrok.exe"
```
### Event ###
```KQL
Event
| where TimeGenerated > ago(90d)
| where EventID == 7045
| extend ParsedXML = parse_xml(EventData)
| where parse_json(tostring(parse_json(tostring(parse_json(tostring(ParsedXML.DataItem)).EventData)).Data))[0].["#text"] has "ngrok"
    or parse_json(tostring(parse_json(tostring(parse_json(tostring(ParsedXML.DataItem)).EventData)).Data))[1].["#text"] has "ngrok.exe"
```
