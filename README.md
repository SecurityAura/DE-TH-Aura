# Detection Engineering & Threat Hunting (DE&TH) by SecurityAura

![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/SecurityAura)
[![Follow me on Bluesky](https://img.shields.io/badge/Bluesky-0285FF?logo=bluesky&logoColor=fff&label=Follow%20me%20on&color=0285FF)](https://bsky.app/profile/securityaura.bsky.social)
![Mastodon Follow](https://img.shields.io/mastodon/follow/109366346067412152?domain=infosec.exchange)

## #100DaysOfKQL Challenge

As of 2025/01/01, a new folder was added for my #100DaysOfKQL challenge. Queries from this challenge will be added there and at some point, after the challenge ends, I'll move them around in the repo in their appropriate sections. I haven't fully thought out the architecture yet.

For more information about my #100DaysOfKQL challenge, see the following Twitter thread:

https://x.com/SecurityAura/status/1874454346324410878

## Introduction

GitHub repository where I'll post anything and everything I want about creating detection, threat hunting and/or even performing investigation in KQL. The queries shared in this repo are mainly aimed at the Microsoft Defender XDR suite of products and/or logs that are ingested through Microsoft Sentinel (e.g.: Windows Security Event Logs).

The queries I come up with are based on different sources of information (or even inspiration). These sources can be:

- Stuff I come across in my day-to-day work
- Tweets
- Blog posts
- Research articles
- Random thoughts/ideas

At some point, I would like to add some pseudo-code using Sigma but for now, it'll be KQL only.

Some queries can be very basic and some can be advanced. The thing with crafting detection, threat hunting queries, etc. is that there's often more than one way of doing it and/or coming up with the same result. Therefore, some of the queries I post could be written in an entirely different way by other people. Some could even be improved upon, because there's always the possibility to build on top of a good base. And this is something I fully expect to do, that is: come back to queries I've posted in the past to improve them for whatever reason there is:

- Maybe I'll have encountered a real-world edge case that we should account for
- Maybe I'll have learned a new KQL function that could be leveraged
- Maybe I'll have found a way to optimize a query
- Or else!

Therefore, expect some changes over time to the queries I post here, because it's never guaranteed that their initial release will be the "final" version. To assist with this, at some point, I'll add a "Query Last Modified" section on each page (a bit like some other people are doing in their KQL repos).

As always, if you have any questions or else about this repo and/or the queries, feel free to drop me a DM on one of the social medias listed above!

## Credits

The template used to create the various pages in this repo comes from Bert-JanP Hunting-Queries-Detection-Rules repo! Make sure to give it a star and follow it!

https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/DetectionTemplate.md
