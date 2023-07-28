
## Overview
**Scenario:** IoT-ENG-WKST is one of the devices that were compromised as part of the intrusion. Incident responder takes the collection from Velociraptor on the IoT Workstation. The team already established that the timeline of the entire attack took place throughout 18:00 - 22:10 UTC on 29 April 2023.


## Host Identification
Details about the host under investigation can be found within its registries: After the acquisition, there are three useful collective host-oriented registries: SYSTEM, SOFTWARE, and SECURITY. These can be found in ``C:\Windows\System32\config\``.

**Hostname:** IOT-ENG-WKST   (Location: ``ControlSet001\Control\ComputerName\ComputerName``)  
**IP Address:** 172.16.50.20 (LOCATION: ``ControlSet001\Services\Tcpip\Parameters\Interfaces\{d94c926b-14ab-4a27-92b2-7901071c2e5c}``)  
**TimeZone:** UTC (Location: ``SYSTEM\CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName``)

An additional host was found through the RDP Cache.
**Hostname:** iot-jumpbox
**IP Address:** 172.16.60.19

---

## Timeline of Threat Actor Actions
**21:29:01 UTC:** Initial Access for the actor into seth.morgan on iot-eng-wkst.magnumtempus.financial from 172.16.40.100. (Windows Event Logs: Security; EventID 4648, 4624, 4672)  
**21:32:34 UTC:** Regained access (Windows Event Logs: Security; EventID 4648, 4624, 4672)  
**21:39:22 UTC:** seth.morgan downloaded map-7.93-setup.exe via Chrome.exe (Windows Event Logs: Sysmon; EventID 1)  
**21:39:33 UTC:** Installed Zenmap (Windows Event Logs: Sysmon)  
**21:40:24-35 UTC:** Execution nmap 172.16.60.0/ 24 -p 3389 -Pn -v  (Windows Event Logs: Sysmon; EventID 1)  
**21:45: UTC:** seth.morgan interacted with 'Jason's Private Folders' and 'Favorite Restaurants', and the '2022-Backup' down to the Operations department  
**21:49:08 UTC:** seth.morgan interacted with Tombstone-Copy folders   
**21:49:39 UTC:** Access to the iot-jumpbox under the username iotadmin (Windows Event Log: Security; EventID 4648)  
**21:49:45 UTC:** mstsc.exe was used for /v:"172.16.60.19" via RDP (Jump List and RDP Cache screenshot)  
**22:50:47 UTC:** Actor conducted nmap scanning, SYN Scan was found (RDP Cache)  
**22:55 UTC:** Accessed ScadaBR's Admin console as admin (RDP Cache)  
**22:59:47 UTC:** Last observed time found (RDP Cache)  
**22:02:19 UTC:** Logoff event from seth.morgan   (Windows Event Logs:  Security; EventID 4634)   

---

## Methodology

My objective is to triage and collect what data that I can find from the logs to determine a starting point.  

Scope the time between the date of the attack 29 April 2023 between 18:00 - 22:10 UTC.  

### High-Level Activity Overview
**Target Artifact(s):** Windows Event Logs   
**Tool(s):** Chainsaw  
Objective is to identify the activity that took place on the device. Even while narrowing down the time, I want to find the needles within the haystack. The tactics, techniques, and procedures (TTP) within an intrusion remain consistent, which can be captured with Sigma rules. Chainsaw is the tool that I used for going through the Windows Event logs to capture the overview.  

``./chainsaw hunt --from '2023-04-29T18:00:00' --to '2023-04-29T22:10:00' /mnt/nvme1n1p1/TEMP_OP/IoT_WKST/uploads/auto/C%3A/Windows/System32/winevt/Logs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --full``

**RESULT:** The activity gives me the starting point on what I need to establish a timeline of events and some key points to dive deeper in to identify what occurred on the workstation in between the time.  

Key points: 
* Initial access into the device
* installation of Nmap suite
* Execution of nmap
* Log-off from the device.

```
IP Address: 172.16.40.100
LogonType: 10
TargeUserName: seth.morgan
TargetUserSid: S-1-5-21-2369732838-3797832421-459094119-1170
WorkstationName: IoT-ENG-WKST
```

### How did they obtain Nmap
**Target Artifact(s):** Browser History  
**Tool(s):** DB Browser Sqlite  
This route was selected first because the Nmap was found within the Downloads folder after being associated with chrome.exe. It's a good point to pivot to the browsing history.  

(Insert 01_BrowserHistory_DBSqlite.png)  
(Insert 02_Browser_Download.png)  

This shows the download url chains with hxxps://nmap[.]org/dist/nmap-7.93-setup.exe  

## How can I prove that the actor executed the file
**Target Artifact(s):** Amcache, Windows Event Logs, Jumplist  
**Tool(s):** AmcacheParser (Zimmerman's Tools), Chainsaw  
Normally, Prefetch would be a good option to review, but because the system that's under investigation is a Windows Server image, there won't be Prefetch available. Instead, there's also the use of Amcache.  

(Insert 03_AmcacheNmap.png)  

Shimcache can show the existence of the file, but not quite the execution.  

From the Windows Event Log, Sysmon shows when the files are executed.  

(Put screenshot from Windows Event Log - Sysmon, later)  

SHA1: ab2de49f90330cc3b305457a9a0f897f296e95f4


The Jump List is useful in finding files executed  

(Show evidence of the Remote Desktop Connection)  

### What Directories and Files did the actor touch
**Target Artifact(s):** JumpList, Shellbag, Lnk Files  
**Tool(s):** JumpList Explorer, Shellbag Explorer, LECmd (Zimmerman's Tools)  

There are multiple evidence to show that the attacker touched the files. Shellbags are useful for identifying the directories that the logged in user went to through the GUI while JumpLists and Link Files can show the files that they touched.



### Where did the threat actor go from there?
**Target Artifact(s):** Windows Event Log and JumpList  
**Tool(s):** Chainsaw and JumpList Explorer, BMC Tools, RDPCacheStitcher
I want to corrolate and corroborate the evidence of RDP activity to another host during the attack.  

(Screenshot of Jump List on Remote Desktop and Windows Event log)  

Another avenue is to find the RDP Bitmap Cache.
```
python3 bmc-tools.py -s '/mnt/nvme1n1p1/TEMP_OP/IoT_WKST/uploads/auto/C%3A/Users/seth.morgan/AppData/Local/Microsoft/Terminal Server Client/Cache/' -d ~/Downloads/BTV -b
```

In order to parse out the cache, another tool was required called RDP Cache Stitcher. 

**Observables (w/ Potential for CTF Questions)**
* Nmap scans were conducted with the following discovery
	* SYN Scan found
  * Port discovery for 8080 found for 172.16.60.16-18, 200, 201
  * 172.16.60.12 had 22(ssh) open
  * 172.16.60.202 had 5900(vnc) and 8080(http-proxy) open
* Actor attempted to ssh into 172.16.60.11 as users **SNSadmin**, **Driller**, **openplc** but was unsuccessful
* Actor attempted to access 172.16.60.202 via VNC (5900) but was unsuccessful
* Actor logged into OpenPLC through 172.16.60.11:8080
* The file for the 'Mud_pump' program is 389456.st
  * This is referred to as the IEC 61131-3 (ST) PLC programs. This is a ladder logic program written for OpenPLC Runtime to understand.
* The actor attempted access 172.16.60.200:8080's ScadaBR login page.
* Actor received an error to the page for 200 and 201. The webserver was Apache/Tomcat/9.0.73
* Managed to get access to ScadaBR under 172.16.60.201:8080 as **admin**
	* Colors observed: Black, green, pink, brown, orange
* Actor stopped Mud_pump program
* Actor was searching through File explorer for **nmap**, **cmd**
	* Originally typo'd **nmap** for **gnmap**



REFERENCE: https://openplcproject.com/docs/3-2-creating-your-first-project-on-openplc-editor/


**Thoughts**
* Working with double screens help a lot with trying to stitch the RDP cache together
* The cache bitmaps are all over the place, so you have to do a lot in order to put them together
* You will not get everything. You will have missing pieces and it will be annoying as hell
* There will feel like repeats or segments of it in different places
* Honestly, you'll probably have to figure out how to manage your expectations and focus on, instead of getting the full picture, try to figure out how to piece together the key points in order to interpret what happened.
*  Expect to look online for references of how certain parts of the screen will look like (i.e. what **nmap**  screen order looks like when in use) to reference them in order because some pieces seem like they fit together, but they don't and you'll suffer for it later if you don't use a reference


**Cheat Sheet by ThatGuyHasDied** - Will cross reference if observed or not
* **HMI 1:** 200   (Observed)
* **HMI 2:** 201   (Observed)
* **HMI 3:** 202   (Observed)
* **HMI 4:** 203   (Not Observed)
* **Mud Pump PLC:** 60.11   (Observed)
* **Top Drive PLC:** 60.13   (Not Observed)
* **Drawworks PLC:** 60.15  (Not Observed)
* **Auxiliary PLC:** 60.17    (Not Observed)
* **MP IO:** 60.12   (Not Observed)
* **TD IO:** 60.14   (Not Observed)
* **DW IO:** 60.16   (Not Observed)
* **Aux IO:** 60.18  (Not Observed)

---

## Artifact Location Reference
### Windows Event Logs
**Typical Location:**  ``C:\Windows\System32\winevt\Logs\``  
**REFERENCE:** https://cybersecuritynews.com/windows-event-log-analysis/  
https://systemweakness.com/list-of-sysmon-event-ids-for-threat-hunting-4250b47cd567  

### Jump Lists
**Typical Location:**   
``C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations``  
``C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination``  
**REFERENCE:** https://frsecure.com/blog/windows-forensics-execution/  
https://artifacts-kb.readthedocs.io/en/latest/sources/windows/JumpLists.html  

### Shellbag
**Typical Location:** ``C:\Users\<username>\NTUser.dat``  
**REFERENCE:** https://medium.com/ce-digital-forensics/shellbag-analysis-18c9b2e87ac7  

### Browser History
**Typical Location:** ``C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default``  
**REFERENCE:** https://www.foxtonforensics.com/browser-history-examiner/chrome-history-location  

### Shimcache
**Typical Location:** ``C:\Windows\System32\config\SYSTEM``  
**Specific Location:** ``HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache``   
**REFERENCE:** https://upadhyayraj.medium.com/windows-artifact-series-amcache-shimcache-prefetch-lnkfiles-jumplist-shellbags-b9bd3dce5c4a  

### Amcache
**Typical Location:** ``C:\Windows\AppCompat\Programs\Amcache.hve``  
**REFERENCE:** https://upadhyayraj.medium.com/windows-artifact-series-amcache-shimcache-prefetch-lnkfiles-jumplist-shellbags-b9bd3dce5c4a  

### Lnk Files
**Typical Location:** ``C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\``  
**REFERENCE:** https://upadhyayraj.medium.com/windows-artifact-series-amcache-shimcache-prefetch-lnkfiles-jumplist-shellbags-b9bd3dce5c4a  

### MFT File
**REFERENCE** https://binaryforay.blogspot.com/2018/06/introducing-mftecmd.html  

### RDP Bitmap Cache: 
**Typical Location:** ``C:\Users\<username>\AppData\Local\Microsoft\Terminal Server Client\Cache``  
**REFERENCE:** https://hejelylab.github.io/blog/IRC/RDP-Bitmap-Cache  
https://medium.com/@ronald.craft/blind-forensics-with-the-rdp-bitmap-cache-16e0c202f91c


## Tools Used with Overview and thoughts
* **Chainsaw:** This tool parses through the Windows Event Logs and can be used to identify specific Event IDs or you can do a complete hunt through the Hunt module. It is recommended to scope the hunt on the time that is suspected to be the attacker's point. As of v2, you have to download the Sigma rules separately.
	* [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
	* [Sigma Rules](https://github.com/SigmaHQ/sigma)
* **Zimmerman Tools:**  This is a complete suite used for going through the registry and file artifacts. There is a tool for each type of artifact. 
	* [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
* **BMC Tools:** Developed by the ANSSI-FR, French CERT, this tool parses through the RDP Bitmap Cache and creates multiple bitmaps for viewing. There is the additional capability to turn it into a collage of files, but the success may vary.  
	* [BMC-Tools](https://github.com/ANSSI-FR/bmc-tools)
* **RDP Cache Stitcher:** This turns the bitmap files created through BMC into a jigsaw puzzle. Definitely recommend having two screens to split the activity for sanity purpose.  
	* [RDPCacheStitcher](https://github.com/BSI-Bund/RdpCacheStitcher)

