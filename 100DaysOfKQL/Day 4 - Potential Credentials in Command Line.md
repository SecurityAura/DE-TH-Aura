# *Potential Cleartext Credentials in Command Line*

## Query Information

This query look for process execution events which may contain/have credentials (cleartext or not) in their command line.

##

#### Description

This is a query which I discussed before and/or even shared a pseudo-code snippet on Twitter. I think Nathan McNulty (@NathanMcNulty) may also have shared something similar at some point.

The idea here is to look for credentials in process command line, which can offer a lot of insights into an organization inherent risk:

- Identify weak passwords
- Identify accounts whose credentials are being passed in the command line directly
- Identify potential password re-use if a password is being used across multiple accounts spotted in the command lines
- Identify potentially unsecured scripts (files) that have credentials in them (e.g.: script on a public share that runs a command as a privileged user)
- Identify accounts whose credentials could be used if a threat actor was to get their hands on that information (e.g.: Event ID 4688, Process Creation event with command line logging, on systems)

More processes may return false positives (e.g.: Chromium-based processes). Simply add them to the ExcludedProcesses variable according to your needs.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
// Excluding known false positive processes
let ExcludedProcesses = dynamic([
    "WerFault.exe",
    "WerFaultSecure.exe",
    "SenseNDR.exe"
]);
// You can add more strings as needed
let PossibleUserCLI = dynamic([
    "/U",
    "/User",
    "/username",
    "-u",
    "-user",
    "--user",
    "--username"
]);
// You can add more strings as needed
let PossiblePasswordCLI = dynamic([
    "/P",
    "/password",
    "/pass",
    "-p",
    "-password",
    "-pw",
    "-pass",
    "--pass",
    "--password"
]);
DeviceProcessEvents
| where not (FileName in~ (ExcludedProcesses))
| where ProcessCommandLine has_any (PossibleUserCLI)
| where ProcessCommandLine has_any (PossiblePasswordCLI)
// Uncomment if you get too many results, just to get a pre-filtering of the results
//| distinct ProcessCommandLine
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
// Excluding known false positive processes
let ExcludedProcesses = dynamic([
    "WerFault.exe",
    "WerFaultSecure.exe",
    "SenseNDR.exe"
]);
// You can add more strings as needed
let PossibleUserCLI = dynamic([
    "/U",
    "/User",
    "/username",
    "-u",
    "-user",
    "--user",
    "--username"
]);
// You can add more strings as needed
let PossiblePasswordCLI = dynamic([
    "/P",
    "/password",
    "/pass",
    "-p",
    "-password",
    "-pw",
    "-pass",
    "--pass",
    "--password"
]);
DeviceProcessEvents
| where not (FileName in~ (ExcludedProcesses))
| where ProcessCommandLine has_any (PossibleUserCLI)
| where ProcessCommandLine has_any (PossiblePasswordCLI)
// Uncomment if you get too many results, just to get a pre-filtering of the results
//| distinct ProcessCommandLine
```
