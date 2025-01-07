# *Files Potentially Holding Sensitive Information*

## Query Information

This query look for file events involving files that may potentially hold sensitive information, such as credentials.

##

#### Description

A query similar to the one shared on Day 4 of #100DaysOfKQL, but for file-based activity. You can define a list of sensitive strings (e.g.: pass, password, passwords, etc.) and look for files that have these strings.

You can also define which kind of files you're looking for, based on their extension (e.g.: DOC, DOCX, TXT, etc.).

This query can help identify potentially unsecured files that may hold sensitive information such as: credentials, secrets, API tokens and the likes. Files that a threat actor could find as well when running basic searches for files with these strings.

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

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
// You can add interesting filename strings as needed
let FileNameStrings = dynamic([
	"pass",
	"password",
	"passwords",
	"cred",
	"creds",
	"credential",
	"credentials",
	"secret",
	"secrets",
	"keys"
]);
// You can add file extensions you may be looking for as needed
let FileExtensions = dynamic([
	"txt",
	"doc",
	"docx",
	"bat",
	"cmd",
	"ps1",
	"rtf",
	"png",
	"jpg",
	"jpeg"
]);
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where FileName has_any (FileNameStrings)
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ (FileExtensions)
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
// You can add interesting filename strings as needed
let FileNameStrings = dynamic([
	"pass",
	"password",
	"passwords",
	"cred",
	"creds",
	"credential",
	"credentials",
	"secret",
	"secrets",
	"keys"
]);
// You can add file extensions you may be looking for as needed
let FileExtensions = dynamic([
	"txt",
	"doc",
	"docx",
	"bat",
	"cmd",
	"ps1",
	"rtf",
	"png",
	"jpg",
	"jpeg"
]);
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where FileName has_any (FileNameStrings)
| extend FileExtension = split(FileName,".")[-1]
| where FileExtension in~ (FileExtensions)
```
