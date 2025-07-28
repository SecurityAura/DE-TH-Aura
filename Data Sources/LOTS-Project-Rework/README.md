# LOTS-Project-Rework #

This folder acts as a "rework" of the original LOTS (Living Off Trusted Sites) Project that was created by @mrd0x (on Twitter/X). The original website still stands to this day:

https://x.com/mrd0x

mrd0x was kind enough to provide me with a sqldump of the LOTS Project website so I could kick-start a CSV version of it.

# Why ? #

The LOTS-Project website never had a CSV and/or JSON export of all its entries, making it hard to incorporate and/or use it in detection and/or threat hunting as an external entity, such as with KQL's externaldata(). Having it as a CSV (and maybe even a JSON someday?) will now make it possible to be used:

- In languages such as KQL that supports the ingestion of external data format (CSV, JSON)
- In solutions that supports the upload of custom tables, lookups, etc. that can be used for enrichment and/or lookup purposes (e.g.: Microsoft Sentinel, Splunk, etc.)
- By scripts (e.g.: PowerShell or Python) that wants to use LOTS as a reference to lookup and/or match sites/domains with other sources (e.g.: audit logs, Web Proxy logs, etc.)

# CSV Columns Breakdown #

Here's a quick breakdown of the various columns now in the CSV:

- id - Legacy column from the sqldump. Will remain for now.
- website - LOTS domain/site
- status - Two (2) possible values: Verified and Unverified. Verified means that there's a Sample for that domain/site confirming that it is indeed used as a LOTS. Unverified means that no Sample (or overall reference) could be found (yet). Though Unverified domains/sites STILL have the potential to be used as LOTS
- site_status - Two (2) possible values: Online or Offline. Online means that I was able to access the website and it was still operating as a LOTS. Offline means that the website was not accessible when I tried to access it. Will remain for now, may discard it in the future.
- site_status_offline_reason - For internal tracking purposes only, why I consider the site to be "Offline"
- status_last_checked - For internal tracking purposes only, date on which I checked the site's status
- source - Two (2) possible values (for now): LOTS Project Original and LOTS Project Rework. The 1st means the domain/site comes from the original LOTS Project. The second are additions that were made when I created the CSV
- tags - The various tags for the domain/site classifying it as a LOTS
- command_and_control - Description for the C&C tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- cli - Description for the C&C tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- download - Description for the Download tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- exfiltration - Description for the Exfiltration tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- paste - Description for the Paste tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- phishing - Description for the Phishing tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- shortener - Description for the Shortener tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- temporary - Description for the Temporary tag of that domain/site. May be discarded in the future and only remain in the UnifiedDescription column.
- samples - Link to a sample on a sandbox service or article, research, blog post, etc. showcasing that domain/site being used as a LOTS
- contributor - Person/user that submitted the LOTS.
- service_provider - Usually, the company behind the LOTS domain/site (usually pulled from copyrights and/or product's company)
- created_at - Date on which the LOTS was created in the project (original) and CSV (rework)
- updated_at - Date on which the LOTS was last updated in the project (original) and CSV (rework)
- UnifiedDescription - A JSON blob which contains the content of the various "description" columns for the tags applied to the domain/site

# New tags #

This CSV comes with new tags, which is one of the main reason why I wanted to rework the original LOTS anyway:

- cli - Means that this site is solely usable via the CLI and/or mainly meant to be used via the CLI
- paste - Means that this is a pastebin-like site, where text is copy/pasted and shared
- shortener - Means that this is a URL shortener service and/or shortened URL
- temporary - Means that this site is a website that allows the free, unregistered upload of files that will expire after a delimited amount of time

The reason why I added these tags is to make it easier to target certain sites/domains based the situation/context. For instance, paste websites being accessed from a Web browser could be benign, however, accessed by a command line interpreter (think PowerShell) with a command that grabs the content of the paste URL and then do something with it (e.g.: decode and write a file to disk) is more suspicious.

More tags MAY be added in the future depending on, honestly, my needs, but also suggestions if they make sense.

# KQL #

Here's the base KQL to use that CSV via externaldata(). What you do after is up to you! I'll be posting/providing more KQL queries leveraging that data soon.

```KQL
let LOTS = externaldata(id: int, website: string, status: string, site_status: string, site_status_offline_reason: string, status_last_checked: string, source: string, tags: string, 
                        command_and_control: string, cli: string, download: string, exfiltration: string, paste: string, phishing: string, shortener: string, temporary: string, samples: string,
                        contributor: string, service_provider: string, created_at: string, updated_at: string, UnifiedDescription: string)
[@"https://raw.githubusercontent.com/SecurityAura/DE-TH-Aura/refs/heads/main/Data%20Sources/LOTS-Project-Rework/LOTS-Project-Rework.csv"]
with (format=csv, ignoreFirstRecord=true)
// Feel free to uncomment the line below if you want one record PER description from UnifiedDescription
//| mv-expand todynamic(UnifiedDescription)
// Uncomment the line below if you want to remove the prefix *. from sites that have them, so that they can be used with has, has_any(), etc. afterwards.
//| extend website = iff (website startswith "*.", trim_start(@'\*\.', website), website)
;
LOTS
```

# Special Thanks #

The rework of LOTS-Project would not have been possible without these precious resources:

- @mrd0x, the OG, who provided a full sqldump of the LOTS-Project website
- @svch0st who provided me a huge list of domains/sites he encountered and could be classified as LOTS
- ANY.RUN and their new Threat Intelligence Lookup service, which allowed to me search for some domains/sites to see if they did fit some tags
- urlscan.io which allowed me to search for domains/sites to see if they did fit some tags, and if these domains/sites were still active (recently submitted and accessible)
