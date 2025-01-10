# *Silent cmd.exe Execution With Redirected STDERR & STDOUT.md*

## Query Information

This query returns instances of cmd.exe that were executed silently where the STDERR and STDOUT outputs are redirected.

##

#### Description

A lot of reverse shells and/or C2s will execute commands that are passed to them via cmd.exe. They may also use the following arguments to keep it stealthy:

- /Q which turns Echo off
- /C which runs the command and then close the window

Additionally, depending on the tool used, the various outputs of the command may be captured in a file (or pipe) which is then sent over and/or read from the remote host (where the command is being sent).

- 2>&1 will redirect the stderr to the stdout (https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/cpp/language-compilers/redirecting-error-command-prompt)

This way, you can still get the stderr/stdout. This method of cmd.exe execution is also part of many open-source projects that are (ab)used by threat actors:

- Impacket - https://github.com/search?q=repo%3Afortra%2Fimpacket%202%3E%261&type=code
- CrackMapExec - https://github.com/search?q=repo%3Abyt3bl33d3r%2FCrackMapExec%202%3E%261&type=code
- NetExec (it's CME successor after all) - https://github.com/search?q=repo%3APennyw0rth%2FNetExec%202%3E%261&type=code

While not specific to OSTs, it's pretty common to see traces of this when it comes to incidents that lead to data exfiltration, ransomware deployment or even where a threat actor was able to get a foothold in an environment. Which makes it a good candidate for a threat hunting query. Run it, review the results and determine if any of the commands launched that way could be reverse-shell related and/or examine their execution context (e.g.: user, parent process, execution timeframe, etc.).

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
- Microsoft Sentinel (via SecurityEvent) - 1 query

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all ("/Q","/C")
| where ProcessCommandLine has_any ("&1","2>&1")
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all ("/Q","/C")
| where ProcessCommandLine has_any ("&1","2>&1")
```
### SecurityEvent - Event ID 4688 (Process Creation) ###
```KQL
SecurityEvent
| where EventID == "4688"
| where Process =~ "cmd.exe"
| where CommandLine has_all ("/Q","/C")
| where CommandLine has_any ("&1","2>&1")
```
