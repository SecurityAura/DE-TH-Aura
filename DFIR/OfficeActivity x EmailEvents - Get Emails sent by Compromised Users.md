# *OfficeActivity x EmailEvents - Get Emails sent by Compromised Users.md*

## Description

The queries below can be used to obtain a summary of all the emails that were sent by a user from a flagged IP address.

## Prerequisite(s) #

- A list of IP addresses that you identified as being malicious, suspicious and/or of interest.
- The auditing of the Send operation for the Exchange OfficeWorkload must be enabled

## Microsoft Sentinel
### Query #1 - Summary of emails sent from flagged Sent operations

This query provides a summary of emails, per their InternetMessageIds, that were sent by Send operations coming from flagged IPs.

The summarization provides you numbers on how many recipients have been targeted "Intra-org" and "Outbound" (external) by InternetMessageId and Subject.
```KQL
let FlaggedIPs = dynamic([
    "1.1.1.1",
    "2.2.2.2"
]);
let InternetMessageIds = (
    OfficeActivity
    | where ClientIP has_any (FlaggedIPs)
    or Client_IPAddress has_any (FlaggedIPs)
    or ActorIpAddress has_any (FlaggedIPs)
    | where Operation == "Send"
    | extend InternetMessageId = tostring(parse_json(Item).InternetMessageId)
    | distinct InternetMessageId
);
EmailEvents
| where InternetMessageId in~ (InternetMessageIds)
| summarize ["ExternalRecipients"]=make_set_if(RecipientEmailAddress,EmailDirection =~ "Outbound"),
            ["InternalRecipients"]=make_set_if(RecipientEmailAddress,EmailDirection =~ "Intra-org")
            by InternetMessageId, Subject
| extend ExternalRecipientsCount = array_length(ExternalRecipients)
| extend InternalRecipientsCount = array_length(InternalRecipients)
| extend SharedRecipients =set_intersect(ExternalRecipients,InternalRecipients)
| extend SharedRecipientsCount=array_length(SharedRecipients)
```
