# *Command Line Interpreter Invoked by Web Application Process (Windows)*

## Query Information

This query return events where a command line interpreter is invoked by a Web Application process on Windows.

##

#### Description

This query return events where a command line interpreter (cmd.exe, powershell.exe or pwsh.exe) is invoked by a Web Application process (e.g.: IIS, Java or Apache) on Windows.

In terms of "low-level detection" or threat hunting, this query definitely fits the bill. One of the most simple way to summarize it is: when a Web application gets exploited and a threat actor uses it to run/launch arbitrary command (e.g.: RCE), most of the time, that command will be launched by the process powering that application.

IIS, Java and Apache are three (3) of the most popular technologies that powers a multitude of websites, applications, etc. (mostly on-premises). Therefore, when a CVE leading to RCE is discovered in any of the application that uses IIS, Java or Apache, or even these technologies themselves, exposed Web applications are often quickly targeting. What they get targeted by however varies, but for some reason, coinminers/cryptominers are always the first to the party (*cough*Kinsing*cough*).

You can definitely modify that query to include the name of the processes that are powering your Web applications to increase coverage. This query is more suited for Threat Hunting rather than detection. To turn it into a detection, you would need to modify the logic to filter on these processes at the InitiatingParentProcessFileName level, the command line interpreters at the InitiatingProcessFileName level AND look for known discovery commands that are quickly executed through RCEs, such as:

- whoami.exe
- hostname.exe
- net.exe
- nltest.exe
- Etc.

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
let CommandLineInterpreters = dynamic([
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe"
]);
let WebApplicationProcesses = dynamic([
    "apache",
    "tomcat",
    "ws_tomcatservice.exe",
    "httpd.exe",
    "nginx.exe",
    "php-cgi.exe",
    "w3wp.exe",
    "java.exe",
    "javaw.exe"
]);
DeviceProcessEvents
| where InitiatingProcessFolderPath has_any (WebApplicationProcesses)
| where FileName in~ (CommandLineInterpreters)
// You may want to start with a distinct filtering to review the results. If so, uncomment the line below.
//| distinct ProcessCommandLine, InitiatingProcessCommandLine
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let CommandLineInterpreters = dynamic([
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe"
]);
let WebApplicationProcesses = dynamic([
    "apache",
    "tomcat",
    "ws_tomcatservice.exe",
    "httpd.exe",
    "nginx.exe",
    "php-cgi.exe",
    "w3wp.exe",
    "java.exe",
    "javaw.exe"
]);
DeviceProcessEvents
| where InitiatingProcessFolderPath has_any (WebApplicationProcesses)
| where FileName in~ (CommandLineInterpreters)
// You may want to start with a distinct filtering to review the results. If so, uncomment the line below.
//| distinct ProcessCommandLine, InitiatingProcessCommandLine
```
