# *Credential Discovery Activity Through findstr.exe and reg.exe*

## Query Information

This query returns events where findstr.exe and reg.exe are potentially being used to search for credentials.

##

#### Description

This query returns events where findstr.exe (for files, folders, etc.) and reg.exe (for the Registry) are potentially being used to search for credentials (passwords, secrets, keys, etc.).

This query is as simple as it sounds: some malware, or most often, threat actor, trying to look for these "low-hanging" fruits credentials using findstr.exe and reg.exe. They'll search for patterns such as: pass, password, secret, key, etc. in hope of finding these unsecured credentials that will allow them to get their hands on other, and hopefully (for them), more privileged accounts.

Probably one of easiest way to look for these old, legacy cPasswords that hadn't been removed from Group Policy Preferences (GPP) files in Sysvol as well.

You can add any interesting string to be alerted on (or returned as result) in this query as well. There may be an overlap with Defender for Endpoint (MDE) built-in detections however, as I've seen alerts triggering by simple findstr.exe for "password" in the past.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let InterestingStrings = dynamic([
    "pass",
    "password",
    "passwords",
    "secret",
    "secrets",
    "key",
    "keys",
    "creds",
    "credential",
    "credentials"
]);
DeviceProcessEvents
| where FileName =~ "findstr.exe"
    or (FileName =~ "reg.exe" and ProcessCommandLine has " query ")
| where ProcessCommandLine has_any (InterestingStrings)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let InterestingStrings = dynamic([
    "pass",
    "password",
    "passwords",
    "secret",
    "secrets",
    "key",
    "keys",
    "creds",
    "credential",
    "credentials"
]);
DeviceProcessEvents
| where FileName =~ "findstr.exe"
    or (FileName =~ "reg.exe" and ProcessCommandLine has " query ")
| where ProcessCommandLine has_any (InterestingStrings)
```
