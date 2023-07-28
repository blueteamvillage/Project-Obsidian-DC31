# WKST07

## WKST07 is an example of an Insider Threat:

A hostile actor (sir.george.pearce@yandex.com) contacted Reggie Habeo to provide a link to ICS_Nmap.Zip and ICS_Nmap.iso files. Reggie subsequently downloaded those files. Analysis determined that these were maliciously modified versions of NMAP that would provide the actor access into the environment.  Investigation is ongoing to determine if Reggie knew that this was malicious software and was colluding with the hostile actor, or if Reggie was duped.  There is no evidence to suggest that the software was installed or the actor gained access to the environment.


**Basic Endpoint Information:**

  - ProductName Windows Server 2022 Datacenter
  - ReleaseID 2009
  - RegisteredOwner EC2
  - InstallDate 2023-04-24 17:23:59Z
  - ComputerName = WKST07
  - TCP/IP Hostname = wkst07
  - Local IP: 172.16.50.137

**TimeZoneInformation key:**
  - ControlSet001\Control\TimeZoneInformation
  - DaylightName -> @tzres.dll,-931
  - StandardName -> @tzres.dll,-932
  - Bias -> 0 (0 hours)
  - ActiveTimeBias -> 0 (0 hours)
  - TimeZoneKeyName-> UTC

**Email Evidence:**

| Timestamp | Activity |
| -- | -- |
| Sat, 29 Apr 2023 13:42:57 -0700 | Email from:<sir.george.pearce@yandex.com> Subject: Beta Testers Needed - New TAM Tool |
| Sat, 29 Apr 2023 15:28:19 -0700 | Email from:<sir.george.pearce@yandex.com> Subject:Here is your beta testing reward!  (PDF Attachment - Amazon Gift Card)|


**MFT Evidence:**

| Timestamp | File Name |
| -- | -- |
| 2023-04-29 20:45:08.2872099 | .\Users\reggie.habeo\Downloads\Beta Testers Needed - New TAM Tool.eml |
| 2023-04-29 20:48:33.7360615 | .\Users\reggie.habeo\Downloads\Beta Instructions.odt |
| 2023-04-29 20:50:21.9098504 | .\Users\reggie.habeo\Downloads\ICS_Nmap.zip |
| 2023-04-29 20:55:53.9385298 | .\Users\reggie.habeo\Downloads\ICS_Nmap ISO.zip |
| 2023-04-29 22:32:07.8306673 | .\Users\reggie.habeo\Downloads\Here is your beta testing reward!.eml | 


**ShellBags Evidence:**

| Timestamp | Access |
| -- | -- |
| 2023-04-29 19:26:19 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan |
| 2023-04-29 19:26:19 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads |
| 2023-04-29 19:26:19 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023 |
| 2023-04-29 20:51:07 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\2022-Backup |
| 2023-04-29 20:51:07 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Projects |
| 2023-04-29 20:51:07 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy |
| 2023-04-29 20:51:02 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Projects\2023 |
| 2023-04-29 20:51:10 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software |
| 2023-04-29 20:55:15 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software\Try 2 |
| 2023-04-29 20:55:15 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software\Try 3 | |
| 2023-04-29 20:55:15 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software\scripts
| 2023-04-29 20:53:59 +00:00 | Desktop\Computers and Devices\172.16.50.146\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software\Try 3\ICS_Nmap ISO |


**A Triage report has been included. It consists of two files:**

1. Collection-wkst04_magnumtempus_financial-2023-06-20T01_01_56Z.htm 
2. sortable-Ach.js

These two files can be downoaded to your machine to review the common Windows artifacts that are collected and analyzed in a triage.  The javascript file allows you to sort the tables in the HTML report by clicking on the column headings.  This is extrememly useful when narrowing the time windows in which the activity occured, and helps to weed out the noise that is not relevant to the investiation.  Both files should be put int the same directory. The triage report does not require any additional software or plugins, and should work with popular browsers.
