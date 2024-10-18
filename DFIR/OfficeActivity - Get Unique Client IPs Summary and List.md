# *OfficeActivity - Get Unique Client IPs Summary, List and Geolocation*

## Description

The queries below can be used to obtain a summary of the various IPs (ClientIP, Client_IPAddress and ActorIpAddress) involved in OfficeActivity events for users of interest.

The ClientIP and Client_IPAddress fields are the most populated, ActorIpAddress rarely is. From what I've seen so far, if both fields are populated (e.g.: ClientIP and Client_IPAddress), they'll have the same value. Though most of the time, only one of them will be populated and the two (2) others will be blank.

From there, you can export that list from Microsoft Sentinel and enrich it externally (through a script, MISP or whatever you want to use).

## Prerequisite(s) #

A list of users you want to investigate further for which you want to get a list of all IP adresses involved in their OfficeActivity events.

## Microsoft Sentinel
### Query #1 - Summary of ClientIP, Client_IPs
```KQL
let Users = dynamic([
    "user1@domain.com",
    "user2@domain.com"
]);
OfficeActivity
| where UserId in~ (Users)
| where not (ipv4_is_in_any_range( ClientIP, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
    or not (ipv4_is_in_any_range( Client_IPAddress, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
    or not (ipv4_is_in_any_range( ActorIpAddress, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
| summarize ClientIPs=make_set(ClientIP),
            ClientIPCount = dcount(ClientIP),
            Client_IPs= make_set(Client_IPAddress),
            Client_IPCount = dcount(Client_IPAddress),
            ActorIps= make_set(ActorIpAddress),
            ActorIPCount = dcount(ActorIpAddress)
            by tolower(UserId)
| extend SharedIps=set_intersect(ClientIPs,Client_IPs)
| extend SharedIpCount=array_length(SharedIps)
| extend AllIPs = array_concat(ClientIPs, Client_IPs)
```
### Query #2 - List of unique IPs involved in the events

Unless you filter it out, the returned count and list may always have a "blank" (empty) field.

```KQL
let Users = dynamic([
    "user1@domain.com",
    "user2@domain.com"
]);
OfficeActivity
| where UserId in~ (Users)
| where not (ipv4_is_in_any_range( ClientIP, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
    or not (ipv4_is_in_any_range( Client_IPAddress, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
    or not (ipv4_is_in_any_range( ActorIpAddress, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
| summarize ClientIPs=make_set(ClientIP),
            ClientIPCount = dcount(ClientIP),
            Client_IPs= make_set(Client_IPAddress),
            Client_IPCount = dcount(Client_IPAddress),
            ActorIps= make_set(ActorIpAddress),
            ActorIPCount = dcount(ActorIpAddress)
            by tolower(UserId)
| extend SharedIps=set_intersect(ClientIPs,Client_IPs)
| extend SharedIpCount=array_length(SharedIps)
| extend AllIPs = array_concat(ClientIPs, Client_IPs)
| mv-expand AllIPs
| distinct tostring(AllIPs)
```
### Query #3 - List of unique IPs involved in the events (with geolocation)
```KQL
let Users = dynamic([
    "user1@domain.com",
    "user2@domain.com"
]);
OfficeActivity
| where UserId in~ (Users)
| where not (ipv4_is_in_any_range( ClientIP, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
    or not (ipv4_is_in_any_range( Client_IPAddress, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
    or not (ipv4_is_in_any_range( ActorIpAddress, dynamic(["192.168.0.0/16","172.16.0.0/12","10.0.0.0/8"])))
| summarize ClientIPs=make_set(ClientIP),
            ClientIPCount = dcount(ClientIP),
            Client_IPs= make_set(Client_IPAddress),
            Client_IPCount = dcount(Client_IPAddress),
            ActorIps= make_set(ActorIpAddress),
            ActorIPCount = dcount(ActorIpAddress)
            by tolower(UserId)
| extend SharedIps=set_intersect(ClientIPs,Client_IPs)
| extend SharedIpCount=array_length(SharedIps)
| extend AllIPs = array_concat(ClientIPs, Client_IPs)
| mv-expand AllIPs
| distinct tostring(AllIPs)
| extend geo_info_from_ip_address(AllIPs)
