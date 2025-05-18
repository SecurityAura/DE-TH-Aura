# *Password of Newly Created User Used Through The CommandLine*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/21 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

This query returns events where the password of a newly created user through "net.exe user" may have been used in a subsequent process creation (through its command line).

A bit of an experimental query I was thinkering with yesterday. A lot of threat actors will create new accounts using "net.exe user" and may afterwards, use it to launch further command while passing along their credentials (e.g.: PsExec.exe).

In these kind of situations, you could potentially identify these commands by simply searching for these passwords in the various processes command lines! Side effect of that query?

- You may spot password reuse, e.g.: multiple users created with the same password
- You may spot weak passwords (e.g.: Password1, Winter2025, etc.)
- Anything fun I haven't thought of yet

The downside with this query is that it will only work if the most basic, but also the most common, form of the "net.exe user" command is used, like so:

- net user TestUser #Password1! /add

This is mostly due to the fact that the various net.exe options aren't position dependent. Which means, this command also works (creates the user):

- net user /active:yes TestUser /comment:"Hello" #Password1! /add

So in this query, we're using the parse_command_line() function to break down the ProcessCommandLine column in a dynamic array, where technically, index 3 would hold our password. Your results are also going to be skewed if someone uses the wrong command, such as trying to add a user to a group, using "net.exe user".

I'll probably go back at some point to try to fix this query, but since it's experimental, it should do the job to get you started/exploring!

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

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let Passwords = (DeviceProcessEvents
| where FileName =~ "net.exe"
| where ProcessCommandLine has_all ("user","/add")
| extend ParsedCLI = parse_command_line(ProcessCommandLine, "windows")
| extend Password = tostring(ParsedCLI[3])
| distinct Password);
DeviceProcessEvents
| where ProcessCommandLine has_any (Passwords)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let Passwords = (DeviceProcessEvents
| where FileName =~ "net.exe"
| where ProcessCommandLine has_all ("user","/add")
| extend ParsedCLI = parse_command_line(ProcessCommandLine, "windows")
| extend Password = tostring(ParsedCLI[3])
| distinct Password);
DeviceProcessEvents
| where ProcessCommandLine has_any (Passwords)
```
