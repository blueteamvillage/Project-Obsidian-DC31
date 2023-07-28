202306252138
Status: #idea
Tags: [[BlueTeamVillage]] - [[Project Obsidian]]
Classification: Internal

## Kill Chain
- The shared drive with the bulk of the corp files died a horrible death on Friday. The IT team has been working overtime to get it back up and running.
- They were unable to restore it exact but had a 1 year old copy of the shared drive, the Rig's files, and some restored files all tucked away in Gdrive.
- Saturday first off, IT will restore a shared drive with all of those files. The Magnum employees are working to move things back and finish up work from Friday.
- The Tombstone crew is online as the new benefits open enrollment from MagnumTempus ends Saturday night and the procrastinators are working to get that taken care of.

## Host Information
**Hostname**: WKST16
**Operating System**: Windows 10 (15.20348)
**NT System Root**: C:\Windows
**User**: Morgan, Seth
**Date**: April 29, 2023

## User Accounts
The below user accounts were identified on the system by reviewing `Windows.Sys.Users.json` in the Velociraptor collector package.

|UID| Account         | UUID                                          | Directory                                   | Created On                   |
| --------------- | --------------------------------------------- | ------------------------------------------- | ---------------------------- |
|18| SYSTEM          | S-1-5-18                                      | %systemroot%\system32\config\systemprofile  | 2021-05-08T08:24:18.988647Z  |
|19| LOCAL SERVICE   | S-1-5-19                                      | %systemroot%\ServiceProfiles\LocalService   | 2021-05-08T08:24:18.988647Z  |
|20| NETWORK SERVICE | S-1-5-20                                      | %systemroot%\ServiceProfiles\NetworkService | 2021-05-08T08:24:18.988647Z  |
|1170| seth.morgan     | S-1-5-21-2369732838-3797832421-459094119-1170 | C:\Users\seth.morgan                        | 2023-04-29T16:20:29.0579038Z |
|500| Administrator   | S-1-5-21-2369732838-3797832421-459094119-500  | C:\Users\Administrator.MAGNUMTEMPUS         | 2023-04-29T21:03:15.8995809Z |
|500| Administrator   |S-1-5-21-542347478-1884741985-3367211439-500	|C:\Users\Administrator	|2023-04-29T18:43:51.5647492Z	|

## Findings
### Interesting Files

| SourceFile                                                                           | FileSize | SourceFileSha256                                                 | Created                      |
| ------------------------------------------------------------------------------------ | -------- | ---------------------------------------------------------------- | ---------------------------- |
| C:\Users\seth.morgan\AppData\Roaming\Microsoft\Windows\Recent\Final_ICS_Nmap.lnk     | 661      | eeb06d0d278144dfc77e4d1892af3b0ec5edeb302c43316335670d4aa58edba9 | 2023-04-29T21:46:50.3312382Z |
| C:\Users\seth.morgan\AppData\Roaming\Microsoft\Windows\Recent\ICS_Nmap.lnk           | 856      | 7c3fdb410d1554191aff0ff97375b18f50c97664c752a628d0a6e5a2cc99f519 | 2023-04-29T21:27:24.5704058Z |
| C:\Users\seth.morgan\AppData\Roaming\Microsoft\Windows\Recent\ICS_Nmap_ISO.lnk       | 627      | ca64ea19a1554fbb07e7064af4e157f7c8416e3c73fabda0de62e81a52df2282 | 2023-04-29T21:27:24.5704058Z |
| C:\Users\seth.morgan\Desktop\Nmap - Zenmap GUI.lnk                                   | 992      | 8f0fdb75daecd282ff379edb6a9724700b8296b8abcdb389f770edb27299e461 | 2023-04-29T21:48:41.1015942Z |
| C:\Users\seth.morgan\Downloads\Final_ICS_Nmap.zip                                    | 30311782 |                                                                  | 2023-04-29T21:46:44.2108531Z |
| C:\Users\seth.morgan\Desktop\Final_ICS_Nmap.zip                                      | 30311782 |                                                                  | 2023-04-29T21:47:11.7592966Z |
| C:\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software\ICS_Nmap ISO.zip | 30297243 |                                                                  | 2023-04-29T20:56:59.1888114Z |
| C:\Users\seth.morgan\Documents\Tombstone-Copy\Software\ISC_Nmap ISO.zip              | 30297243 |                                                                  | 2023-04-29T22:09:47.3895164Z |

The following files were found in the collection pack at `WKST16-Disk/Collection-wkst16_magnumtempus_financial-2023-06-17T06_12_26Z/data/uploads/auto/C%3A/$Recycle.Bin/S-1-5-21-2369732838-3797832421-459094119-1170` indicating that they had also been deleted from the user account. 

```
�P��$�z�,C:\Users\seth.morgan\Desktop\ICS_PLUGIN.EXE
�L���VG�z�.C:\Users\seth.morgan\Desktop\ICS_Nmap ISO.zip
xE�P��$�z�1C:\Users\seth.morgan\Desktop\NMAP_7_93_SETUP.EXE
�P��$�z�)C:\Users\seth.morgan\Desktop\INSTALL.BAT
���s�%�z�%C:\Users\seth.morgan\Desktop\SCRIPTS\
(�P��$�z�,C:\Users\seth.morgan\Desktop\NPCAP_1_74.EXE
��VG�z�*C:\Users\seth.morgan\Desktop\ICS_Nmap ISO%
```

### Command Line History
A limited console history was collected from `/WKST16-Disk/Collection-wkst16_magnumtempus_financial-2023-06-17T06_12_26Z/data/uploads/auto/C%3A/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`. Because timestamps are not captured here, it is unclear if this was basic system administration or actor activity. 

```
net localgroup administrators
net localgroup administrators seth.morgan
net localgroup administrators seth.morgan /add
net localgroup administrators seth.morgan
net localgroup administrators
hostname
time
Get-Date
```

### Windows Event Logs
Windows OS generated events were reviewed from the Velociraptor collection package (`\data\uploads\auto\C%3A\Windows\System32\winevt\Logs\Security.evtx`) and the following interesting artifacts were located through manual analysis and through the use of DeepBlueCLI (https://github.com/sans-blue-team/DeepBlueCLI).  As the scope of the attack is not clearly evident nor is the timeline, the investigator will have to take into account all anomalous activity. 

```
Date    : 4/29/2023 2:45:35 PM
Log     : Security
EventID : 4732
Message : User added to local Administrators group
Results : Username: -
          User SID: S-1-5-21-2369732838-3797832421-459094119-1170

Command :
Decoded :

Date    : 4/29/2023 12:33:16 PM
Log     : Security
EventID : 4648
Message : Distributed Account Explicit Credential Use (Password Spray Attack)
Results : The use of multiple user account access attempts with explicit credentials is an indicator of a password spray attack.
          Target Usernames: UMFD-4 DWM-4 UMFD-5 WKST16$ DWM-5 UMFD-3 seth.morgan Administrator DWM-3
          Unique accounts sprayed: 9
          Accessing Username: WKST16$
          Accessing Host Name: MAGNUMTEMPUS

Command :
Decoded :

Date    : 4/27/2023 11:17:39 PM
Log     : Security
EventID : 4732
Message : User added to local Administrators group
Results : Username: -
          User SID: S-1-5-21-2369732838-3797832421-459094119-512

Command :
Decoded :
```
 
 and from `""/system.evtx`
 
 ```
 Date    : 4/28/2023 12:50:11 AM
Log     : System
EventID : 7036
Message : Suspicious Service Name
Results : Service name: ShellHWDetection
          Metasploit-style service name: 16 characters
Command :
Decoded :

Date    : 4/28/2023 12:50:09 AM
Log     : System
EventID : 7036
Message : Suspicious Service Name
Results : Service name: CoreMessagingRegistrar
          Metasploit-style service name: 22 characters
Command :
Decoded :
```

and from `Windows Powershell.evtx` 

```
Log Name:      Windows PowerShell
Source:        PowerShell
Date:          4/28/2023 8:45:26 PM
Event ID:      403
Task Category: Engine Lifecycle
Level:         Information
Keywords:      Classic
User:          N/A
Computer:      wkst16.magnumtempus.financial
Description:
Engine state is changed from Available to Stopped. 

Details: 
	NewEngineState=Stopped
	PreviousEngineState=Available

	SequenceNumber=15

	HostName=ConsoleHost
	HostVersion=5.1.20348.1366
	HostId=e73ac253-6a78-45e4-9af4-c8ac3000821f
	HostApplication=PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAgAC0ARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIABVAG4AcgBlAHMAdAByAGkAYwB0AGUAZAAgAC0ARQBuAGMAbwBkAGUAZABDAG8AbQBtAGEAbgBkACAASgBnAEIAagBBAEcAZwBBAFkAdwBCAHcAQQBDADQAQQBZAHcAQgB2AEEARwAwAEEASQBBAEEAMgBBAEQAVQBBAE0AQQBBAHcAQQBEAEUAQQBJAEEAQQArAEEAQwBBAEEASgBBAEIAdQBBAEgAVQBBAGIAQQBCAHMAQQBBAG8AQQBhAFEAQgBtAEEAQwBBAEEASwBBAEEAawBBAEYAQQBBAFUAdwBCAFcAQQBHAFUAQQBjAGcAQgB6AEEARwBrAEEAYgB3AEIAdQBBAEYAUQBBAFkAUQBCAGkAQQBHAHcAQQBaAFEAQQB1AEEARgBBAEEAVQB3AEIAVwBBAEcAVQBBAGMAZwBCAHoAQQBHAGsAQQBiAHcAQgB1AEEAQwBBAEEATABRAEIAcwBBAEgAUQBBAEkAQQBCAGIAQQBGAFkAQQBaAFEAQgB5AEEASABNAEEAYQBRAEIAdgBBAEcANABBAFgAUQBBAGkAQQBEAE0AQQBMAGcAQQB3AEEAQwBJAEEASwBRAEEAZwBBAEgAcwBBAEMAZwBBAG4AQQBIAHMAQQBJAGcAQgBtAEEARwBFAEEAYQBRAEIAcwBBAEcAVQBBAFoAQQBBAGkAQQBEAG8AQQBkAEEAQgB5AEEASABVAEEAWgBRAEEAcwBBAEMASQBBAGIAUQBCAHoAQQBHAGMAQQBJAGcAQQA2AEEAQwBJAEEAUQBRAEIAdQBBAEgATQBBAGEAUQBCAGkAQQBHAHcAQQBaAFEAQQBnAEEASABJAEEAWgBRAEIAeABBAEgAVQBBAGEAUQBCAHkAQQBHAFUAQQBjAHcAQQBnAEEARgBBAEEAYgB3AEIAMwBBAEcAVQBBAGMAZwBCAFQAQQBHAGcAQQBaAFEAQgBzAEEARwB3AEEASQBBAEIAMgBBAEQATQBBAEwAZwBBAHcAQQBDAEEAQQBiAHcAQgB5AEEAQwBBAEEAYgBnAEIAbABBAEgAYwBBAFoAUQBCAHkAQQBDAEkAQQBmAFEAQQBuAEEAQQBvAEEAWgBRAEIANABBAEcAawBBAGQAQQBBAGcAQQBEAEUAQQBDAGcAQgA5AEEAQQBvAEEASgBBAEIAbABBAEgAZwBBAFoAUQBCAGoAQQBGADgAQQBkAHcAQgB5AEEARwBFAEEAYwBBAEIAdwBBAEcAVQBBAGMAZwBCAGYAQQBIAE0AQQBkAEEAQgB5AEEAQwBBAEEAUABRAEEAZwBBAEMAUQBBAGEAUQBCAHUAQQBIAEEAQQBkAFEAQgAwAEEAQwBBAEEAZgBBAEEAZwBBAEUAOABBAGQAUQBCADAAQQBDADAAQQBVAHcAQgAwAEEASABJAEEAYQBRAEIAdQBBAEcAYwBBAEMAZwBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQQBnAEEARAAwAEEASQBBAEEAawBBAEcAVQBBAGUAQQBCAGwAQQBHAE0AQQBYAHcAQgAzAEEASABJAEEAWQBRAEIAdwBBAEgAQQBBAFoAUQBCAHkAQQBGADgAQQBjAHcAQgAwAEEASABJAEEATABnAEIAVABBAEgAQQBBAGIAQQBCAHAAQQBIAFEAQQBLAEEAQgBBAEEAQwBnAEEASQBnAEIAZwBBAEQAQQBBAFkAQQBBAHcAQQBHAEEAQQBNAEEAQgBnAEEARABBAEEASQBnAEEAcABBAEMAdwBBAEkAQQBBAHkAQQBDAHcAQQBJAEEAQgBiAEEARgBNAEEAZABBAEIAeQBBAEcAawBBAGIAZwBCAG4AQQBGAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAUABBAEgAQQBBAGQAQQBCAHAAQQBHADgAQQBiAGcAQgB6AEEARgAwAEEATwBnAEEANgBBAEYASQBBAFoAUQBCAHQAQQBHADgAQQBkAGcAQgBsAEEARQBVAEEAYgBRAEIAdwBBAEgAUQBBAGUAUQBCAEYAQQBHADQAQQBkAEEAQgB5AEEARwBrAEEAWgBRAEIAegBBAEMAawBBAEMAZwBCAEoAQQBHAFkAQQBJAEEAQQBvAEEAQwAwAEEAYgBnAEIAdgBBAEgAUQBBAEkAQQBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQQB1AEEARQB3AEEAWgBRAEIAdQBBAEcAYwBBAGQAQQBCAG8AQQBDAEEAQQBMAFEAQgBsAEEASABFAEEASQBBAEEAeQBBAEMAawBBAEkAQQBCADcAQQBDAEEAQQBkAEEAQgBvAEEASABJAEEAYgB3AEIAMwBBAEMAQQBBAEkAZwBCAHAAQQBHADQAQQBkAGcAQgBoAEEARwB3AEEAYQBRAEIAawBBAEMAQQBBAGMAQQBCAGgAQQBIAGsAQQBiAEEAQgB2AEEARwBFAEEAWgBBAEEAaQBBAEMAQQBBAGYAUQBBAEsAQQBGAE0AQQBaAFEAQgAwAEEAQwAwAEEAVgBnAEIAaABBAEgASQBBAGEAUQBCAGgAQQBHAEkAQQBiAEEAQgBsAEEAQwBBAEEATABRAEIATwBBAEcARQBBAGIAUQBCAGwAQQBDAEEAQQBhAGcAQgB6AEEARwA4AEEAYgBnAEIAZgBBAEgASQBBAFkAUQBCADMAQQBDAEEAQQBMAFEAQgBXAEEARwBFAEEAYgBBAEIAMQBBAEcAVQBBAEkAQQBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQgBiAEEARABFAEEAWABRAEEASwBBAEMAUQBBAFoAUQBCADQAQQBHAFUAQQBZAHcAQgBmAEEASABjAEEAYwBnAEIAaABBAEgAQQBBAGMAQQBCAGwAQQBIAEkAQQBJAEEAQQA5AEEAQwBBAEEAVwB3AEIAVABBAEcATQBBAGMAZwBCAHAAQQBIAEEAQQBkAEEAQgBDAEEARwB3AEEAYgB3AEIAagBBAEcAcwBBAFgAUQBBADYAQQBEAG8AQQBRAHcAQgB5AEEARwBVAEEAWQBRAEIAMABBAEcAVQBBAEsAQQBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQgBiAEEARABBAEEAWABRAEEAcABBAEEAbwBBAEoAZwBBAGsAQQBHAFUAQQBlAEEAQgBsAEEARwBNAEEAWAB3AEIAMwBBAEgASQBBAFkAUQBCAHcAQQBIAEEAQQBaAFEAQgB5AEEAQQA9AD0A
	EngineVersion=5.1.20348.1366
	RunspaceId=7c69595c-6008-44d7-8040-f1a38883abe0
	PipelineId=
	CommandName=
	CommandType=
	ScriptName=
	CommandPath=
	CommandLine=
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="PowerShell" />
    <EventID Qualifiers="0">403</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>4</Task>
    <Opcode>0</Opcode>
    <Keywords>0x80000000000000</Keywords>
    <TimeCreated SystemTime="2023-04-29T00:45:26.9778366Z" />
    <EventRecordID>44720</EventRecordID>
    <Correlation />
    <Execution ProcessID="0" ThreadID="0" />
    <Channel>Windows PowerShell</Channel>
    <Computer>wkst16.magnumtempus.financial</Computer>
    <Security />
  </System>
  <EventData>
    <Data>Stopped</Data>
    <Data>Available</Data>
    <Data>	NewEngineState=Stopped
	PreviousEngineState=Available

	SequenceNumber=15

	HostName=ConsoleHost
	HostVersion=5.1.20348.1366
	HostId=e73ac253-6a78-45e4-9af4-c8ac3000821f
	HostApplication=PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAgAC0ARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIABVAG4AcgBlAHMAdAByAGkAYwB0AGUAZAAgAC0ARQBuAGMAbwBkAGUAZABDAG8AbQBtAGEAbgBkACAASgBnAEIAagBBAEcAZwBBAFkAdwBCAHcAQQBDADQAQQBZAHcAQgB2AEEARwAwAEEASQBBAEEAMgBBAEQAVQBBAE0AQQBBAHcAQQBEAEUAQQBJAEEAQQArAEEAQwBBAEEASgBBAEIAdQBBAEgAVQBBAGIAQQBCAHMAQQBBAG8AQQBhAFEAQgBtAEEAQwBBAEEASwBBAEEAawBBAEYAQQBBAFUAdwBCAFcAQQBHAFUAQQBjAGcAQgB6AEEARwBrAEEAYgB3AEIAdQBBAEYAUQBBAFkAUQBCAGkAQQBHAHcAQQBaAFEAQQB1AEEARgBBAEEAVQB3AEIAVwBBAEcAVQBBAGMAZwBCAHoAQQBHAGsAQQBiAHcAQgB1AEEAQwBBAEEATABRAEIAcwBBAEgAUQBBAEkAQQBCAGIAQQBGAFkAQQBaAFEAQgB5AEEASABNAEEAYQBRAEIAdgBBAEcANABBAFgAUQBBAGkAQQBEAE0AQQBMAGcAQQB3AEEAQwBJAEEASwBRAEEAZwBBAEgAcwBBAEMAZwBBAG4AQQBIAHMAQQBJAGcAQgBtAEEARwBFAEEAYQBRAEIAcwBBAEcAVQBBAFoAQQBBAGkAQQBEAG8AQQBkAEEAQgB5AEEASABVAEEAWgBRAEEAcwBBAEMASQBBAGIAUQBCAHoAQQBHAGMAQQBJAGcAQQA2AEEAQwBJAEEAUQBRAEIAdQBBAEgATQBBAGEAUQBCAGkAQQBHAHcAQQBaAFEAQQBnAEEASABJAEEAWgBRAEIAeABBAEgAVQBBAGEAUQBCAHkAQQBHAFUAQQBjAHcAQQBnAEEARgBBAEEAYgB3AEIAMwBBAEcAVQBBAGMAZwBCAFQAQQBHAGcAQQBaAFEAQgBzAEEARwB3AEEASQBBAEIAMgBBAEQATQBBAEwAZwBBAHcAQQBDAEEAQQBiAHcAQgB5AEEAQwBBAEEAYgBnAEIAbABBAEgAYwBBAFoAUQBCAHkAQQBDAEkAQQBmAFEAQQBuAEEAQQBvAEEAWgBRAEIANABBAEcAawBBAGQAQQBBAGcAQQBEAEUAQQBDAGcAQgA5AEEAQQBvAEEASgBBAEIAbABBAEgAZwBBAFoAUQBCAGoAQQBGADgAQQBkAHcAQgB5AEEARwBFAEEAYwBBAEIAdwBBAEcAVQBBAGMAZwBCAGYAQQBIAE0AQQBkAEEAQgB5AEEAQwBBAEEAUABRAEEAZwBBAEMAUQBBAGEAUQBCAHUAQQBIAEEAQQBkAFEAQgAwAEEAQwBBAEEAZgBBAEEAZwBBAEUAOABBAGQAUQBCADAAQQBDADAAQQBVAHcAQgAwAEEASABJAEEAYQBRAEIAdQBBAEcAYwBBAEMAZwBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQQBnAEEARAAwAEEASQBBAEEAawBBAEcAVQBBAGUAQQBCAGwAQQBHAE0AQQBYAHcAQgAzAEEASABJAEEAWQBRAEIAdwBBAEgAQQBBAFoAUQBCAHkAQQBGADgAQQBjAHcAQgAwAEEASABJAEEATABnAEIAVABBAEgAQQBBAGIAQQBCAHAAQQBIAFEAQQBLAEEAQgBBAEEAQwBnAEEASQBnAEIAZwBBAEQAQQBBAFkAQQBBAHcAQQBHAEEAQQBNAEEAQgBnAEEARABBAEEASQBnAEEAcABBAEMAdwBBAEkAQQBBAHkAQQBDAHcAQQBJAEEAQgBiAEEARgBNAEEAZABBAEIAeQBBAEcAawBBAGIAZwBCAG4AQQBGAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAUABBAEgAQQBBAGQAQQBCAHAAQQBHADgAQQBiAGcAQgB6AEEARgAwAEEATwBnAEEANgBBAEYASQBBAFoAUQBCAHQAQQBHADgAQQBkAGcAQgBsAEEARQBVAEEAYgBRAEIAdwBBAEgAUQBBAGUAUQBCAEYAQQBHADQAQQBkAEEAQgB5AEEARwBrAEEAWgBRAEIAegBBAEMAawBBAEMAZwBCAEoAQQBHAFkAQQBJAEEAQQBvAEEAQwAwAEEAYgBnAEIAdgBBAEgAUQBBAEkAQQBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQQB1AEEARQB3AEEAWgBRAEIAdQBBAEcAYwBBAGQAQQBCAG8AQQBDAEEAQQBMAFEAQgBsAEEASABFAEEASQBBAEEAeQBBAEMAawBBAEkAQQBCADcAQQBDAEEAQQBkAEEAQgBvAEEASABJAEEAYgB3AEIAMwBBAEMAQQBBAEkAZwBCAHAAQQBHADQAQQBkAGcAQgBoAEEARwB3AEEAYQBRAEIAawBBAEMAQQBBAGMAQQBCAGgAQQBIAGsAQQBiAEEAQgB2AEEARwBFAEEAWgBBAEEAaQBBAEMAQQBBAGYAUQBBAEsAQQBGAE0AQQBaAFEAQgAwAEEAQwAwAEEAVgBnAEIAaABBAEgASQBBAGEAUQBCAGgAQQBHAEkAQQBiAEEAQgBsAEEAQwBBAEEATABRAEIATwBBAEcARQBBAGIAUQBCAGwAQQBDAEEAQQBhAGcAQgB6AEEARwA4AEEAYgBnAEIAZgBBAEgASQBBAFkAUQBCADMAQQBDAEEAQQBMAFEAQgBXAEEARwBFAEEAYgBBAEIAMQBBAEcAVQBBAEkAQQBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQgBiAEEARABFAEEAWABRAEEASwBBAEMAUQBBAFoAUQBCADQAQQBHAFUAQQBZAHcAQgBmAEEASABjAEEAYwBnAEIAaABBAEgAQQBBAGMAQQBCAGwAQQBIAEkAQQBJAEEAQQA5AEEAQwBBAEEAVwB3AEIAVABBAEcATQBBAGMAZwBCAHAAQQBIAEEAQQBkAEEAQgBDAEEARwB3AEEAYgB3AEIAagBBAEcAcwBBAFgAUQBBADYAQQBEAG8AQQBRAHcAQgB5AEEARwBVAEEAWQBRAEIAMABBAEcAVQBBAEsAQQBBAGsAQQBIAE0AQQBjAEEAQgBzAEEARwBrAEEAZABBAEIAZgBBAEgAQQBBAFkAUQBCAHkAQQBIAFEAQQBjAHcAQgBiAEEARABBAEEAWABRAEEAcABBAEEAbwBBAEoAZwBBAGsAQQBHAFUAQQBlAEEAQgBsAEEARwBNAEEAWAB3AEIAMwBBAEgASQBBAFkAUQBCAHcAQQBIAEEAQQBaAFEAQgB5AEEAQQA9AD0A
	EngineVersion=5.1.20348.1366
	RunspaceId=7c69595c-6008-44d7-8040-f1a38883abe0
	PipelineId=
	CommandName=
	CommandType=
	ScriptName=
	CommandPath=
	CommandLine=</Data>
  </EventData>
</Event>
```

The encoded payload here is a base64 string which decodes to:

```
PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand JgBjAGgAYwBwAC4AYwBvAG0AIAA2ADUAMAAwADEAIAA+ACAAJABuAHUAbABsAAoAaQBmACAAKAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuACAALQBsAHQAIABbAFYAZQByAHMAaQBvAG4AXQAiADMALgAwACIAKQAgAHsACgAnAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnAAoAZQB4AGkAdAAgADEACgB9AAoAJABlAHgAZQBjAF8AdwByAGEAcABwAGUAcgBfAHMAdAByACAAPQAgACQAaQBuAHAAdQB0ACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAgAD0AIAAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAF8AcwB0AHIALgBTAHAAbABpAHQAKABAACgAIgBgADAAYAAwAGAAMABgADAAIgApACwAIAAyACwAIABbAFMAdAByAGkAbgBnAFMAcABsAGkAdABPAHAAdABpAG8AbgBzAF0AOgA6AFIAZQBtAG8AdgBlAEUAbQBwAHQAeQBFAG4AdAByAGkAZQBzACkACgBJAGYAIAAoAC0AbgBvAHQAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAuAEwAZQBuAGcAdABoACAALQBlAHEAIAAyACkAIAB7ACAAdABoAHIAbwB3ACAAIgBpAG4AdgBhAGwAaQBkACAAcABhAHkAbABvAGEAZAAiACAAfQAKAFMAZQB0AC0AVgBhAHIAaQBhAGIAbABlACAALQBOAGEAbQBlACAAagBzAG8AbgBfAHIAYQB3ACAALQBWAGEAbAB1AGUAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADEAXQAKACQAZQB4AGUAYwBfAHcAcgBhAHAAcABlAHIAIAA9ACAAWwBTAGMAcgBpAHAAdABCAGwAbwBjAGsAXQA6ADoAQwByAGUAYQB0AGUAKAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADAAXQApAAoAJgAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAA==
```

Further decoded, the payload actually appears to be a deadend referencing Ansible and was most likely used in the creation of the workstation. 

```
❯ echo JgBjAGgAYwBwAC4AYwBvAG0AIAA2ADUAMAAwADEAIAA+ACAAJABuAHUAbABsAAoAaQBmACAAKAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuACAALQBsAHQAIABbAFYAZQByAHMAaQBvAG4AXQAiADMALgAwACIAKQAgAHsACgAnAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnAAoAZQB4AGkAdAAgADEACgB9AAoAJABlAHgAZQBjAF8AdwByAGEAcABwAGUAcgBfAHMAdAByACAAPQAgACQAaQBuAHAAdQB0ACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAgAD0AIAAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAF8AcwB0AHIALgBTAHAAbABpAHQAKABAACgAIgBgADAAYAAwAGAAMABgADAAIgApACwAIAAyACwAIABbAFMAdAByAGkAbgBnAFMAcABsAGkAdABPAHAAdABpAG8AbgBzAF0AOgA6AFIAZQBtAG8AdgBlAEUAbQBwAHQAeQBFAG4AdAByAGkAZQBzACkACgBJAGYAIAAoAC0AbgBvAHQAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAuAEwAZQBuAGcAdABoACAALQBlAHEAIAAyACkAIAB7ACAAdABoAHIAbwB3ACAAIgBpAG4AdgBhAGwAaQBkACAAcABhAHkAbABvAGEAZAAiACAAfQAKAFMAZQB0AC0AVgBhAHIAaQBhAGIAbABlACAALQBOAGEAbQBlACAAagBzAG8AbgBfAHIAYQB3ACAALQBWAGEAbAB1AGUAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADEAXQAKACQAZQB4AGUAYwBfAHcAcgBhAHAAcABlAHIAIAA9ACAAWwBTAGMAcgBpAHAAdABCAGwAbwBjAGsAXQA6ADoAQwByAGUAYQB0AGUAKAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADAAXQApAAoAJgAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAA== | base64 -d
&chcp.com 65001 > $null
if ($PSVersionTable.PSVersion -lt [Version]"3.0") {
'{"failed":true,"msg":"Ansible requires PowerShell v3.0 or newer"}'
exit 1
}
$exec_wrapper_str = $input | Out-String
$split_parts = $exec_wrapper_str.Split(@("`0`0`0`0"), 2, [StringSplitOptions]::RemoveEmptyEntries)
If (-not $split_parts.Length -eq 2) { throw "invalid payload" }
Set-Variable -Name json_raw -Value $split_parts[1]
$exec_wrapper = [ScriptBlock]::Create($split_parts[0])
&$exec_wrapper%
```

## Timeline

| User        | visit_time           | visited_url                                                                             | title                         |
| ----------- | -------------------- | --------------------------------------------------------------------------------------- | ----------------------------- |
| seth.morgan | 2023-04-29T18:15:52Z | https://drive.google.com/drive/folders/1FeFMIqhQ9L1iq_b2lOc_2KHVVWDiD-4N?usp=share_link | 2022-Backup - Google Drive    |
| seth.morgan | 2023-04-29T18:15:54Z | https://drive.google.com/drive/folders/1FeFMIqhQ9L1iq_b2lOc_2KHVVWDiD-4N                | 2022-Backup - Google Drive    |
| seth.morgan | 2023-04-29T18:15:55Z | https://drive.google.com/drive/folders/1FeFMIqhQ9L1iq_b2lOc_2KHVVWDiD-4N                | 2022-Backup - Google Drive    |
| seth.morgan | 2023-04-29T18:34:15Z | https://drive.google.com/drive/folders/1gRVbnSoDcv2uefcliYRhHSwjSak0nihT?usp=share_link | Tombstone-Copy - Google Drive |
| seth.morgan | 2023-04-29T18:34:15Z | https://drive.google.com/drive/folders/1gRVbnSoDcv2uefcliYRhHSwjSak0nihT                | Tombstone-Copy - Google Drive |
| seth.morgan | 2023-04-29T18:34:16Z | https://drive.google.com/drive/folders/1gRVbnSoDcv2uefcliYRhHSwjSak0nihT                | Tombstone-Copy - Google Drive |
| seth.morgan | 2023-04-29T19:37:51Z | https://drive.google.com/drive/folders/1gRVbnSoDcv2uefcliYRhHSwjSak0nihT                | Tombstone-Copy - Google Drive |
| seth.morgan | 2023-04-29T19:37:53Z | https://drive.google.com/drive/folders/1gRVbnSoDcv2uefcliYRhHSwjSak0nihT                | Tombstone-Copy - Google Drive |
    |     |     |

   
## Memory Interrogation

1. Leveraging the Volatility framework, I started with the `windows.malfind` plugin to identify any suspicious binaries running in memory.    While several artifacts were located, one thing that presented several times as PID `10292` was `powershell.exe` which is a very common method of in memory code execution.
	 ![[Pasted image 20230626214845.png]]
	 ![[Pasted image 20230626215243.png]]
 2. Zooming in on this process and it's dependants, it appears that the process was original started from `userinit.exe > explorer.exe`
    ![[Pasted image 20230626215643.png]]
3. Switching over to the Velo artifact collection, the `Windows.System.PSList` was reviewed for the same processes, however no positive connection was made.


### PSList
```
❯ vol -f PhysicalMemory.raw windows.pslist
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4	0	System	0x98835c481040	143	-	N/A	False	2023-04-28 04:50:04.000000 	N/A	Disabled
96	4	Registry	0x98835c5c8040	4	-	N/A	False	2023-04-28 04:50:02.000000 	N/A	Disabled
308	4	smss.exe	0x98835ce50040	2	-	N/A	False	2023-04-28 04:50:04.000000 	N/A	Disabled
420	412	csrss.exe	0x9883602e4140	10	-	0	False	2023-04-28 04:50:06.000000 	N/A	Disabled
492	412	wininit.exe	0x988360387140	2	-	0	False	2023-04-28 04:50:07.000000 	N/A	Disabled
500	484	csrss.exe	0x98836038a080	9	-	1	False	2023-04-28 04:50:07.000000 	N/A	Disabled
560	484	winlogon.exe	0x9883603c7080	2	-	1	False	2023-04-28 04:50:07.000000 	N/A	Disabled
628	492	services.exe	0x9883603df180	9	-	0	False	2023-04-28 04:50:07.000000 	N/A	Disabled
640	492	lsass.exe	0x988360385140	10	-	0	False	2023-04-28 04:50:07.000000 	N/A	Disabled
752	628	svchost.exe	0x988361071300	22	-	0	False	2023-04-28 04:50:08.000000 	N/A	Disabled
780	560	fontdrvhost.ex	0x98836107a280	5	-	1	False	2023-04-28 04:50:08.000000 	N/A	Disabled
784	492	fontdrvhost.ex	0x98836100b300	5	-	0	False	2023-04-28 04:50:08.000000 	N/A	Disabled
864	628	svchost.exe	0x9883610c3380	15	-	0	False	2023-04-28 04:50:08.000000 	N/A	Disabled
916	628	svchost.exe	0x98836112b340	5	-	0	False	2023-04-28 04:50:08.000000 	N/A	Disabled
992	560	LogonUI.exe	0x988361154180	9	-	1	False	2023-04-28 04:50:08.000000 	N/A	Disabled
1020	560	dwm.exe	0x988361190100	17	-	1	False	2023-04-28 04:50:09.000000 	N/A	Disabled
416	628	svchost.exe	0x9883611a43c0	37	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
700	628	svchost.exe	0x9883611ce340	4	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
776	628	svchost.exe	0x9883611cc0c0	3	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
880	628	svchost.exe	0x9883611d03c0	4	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
988	628	svchost.exe	0x9883611cd080	1	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
1092	628	svchost.exe	0x98836124c080	7	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
1140	628	svchost.exe	0x9883612883c0	12	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
1172	628	svchost.exe	0x9883612a03c0	2	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
1196	628	svchost.exe	0x9883612a6080	12	-	0	False	2023-04-28 04:50:09.000000 	N/A	Disabled
1364	628	svchost.exe	0x988361329380	6	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1384	628	svchost.exe	0x9883613273c0	5	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1392	628	svchost.exe	0x98836131d340	9	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1420	628	svchost.exe	0x98836138d340	3	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1444	628	svchost.exe	0x9883613a43c0	9	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1460	628	svchost.exe	0x9883613a93c0	13	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1476	628	svchost.exe	0x9883613ab340	3	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1668	628	svchost.exe	0x98836148f340	6	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1736	628	svchost.exe	0x988361499340	4	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1804	628	svchost.exe	0x9883614ed340	13	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1816	628	svchost.exe	0x9883615020c0	2	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1832	628	svchost.exe	0x98836150d3c0	7	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1844	628	svchost.exe	0x9883615153c0	3	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1852	628	svchost.exe	0x988361519080	5	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1884	628	svchost.exe	0x9883615763c0	7	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1956	628	svchost.exe	0x9883615ae340	3	-	0	False	2023-04-28 04:50:10.000000 	N/A	Disabled
1180	628	svchost.exe	0x98836162c080	3	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2124	628	svchost.exe	0x98835c50e080	5	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2136	628	svchost.exe	0x98835c4f5080	4	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2296	628	svchost.exe	0x98836162e080	6	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2448	628	spoolsv.exe	0x9883616c5080	9	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2572	628	svchost.exe	0x9883616c1080	15	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2588	628	amazon-ssm-age	0x9883616c0080	12	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2612	628	svchost.exe	0x9883616be080	7	-	0	False	2023-04-28 04:50:11.000000 	N/A	Disabled
2668	628	svchost.exe	0x9883616bd080	7	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
2748	628	svchost.exe	0x9883616ba080	4	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
2776	628	svchost.exe	0x9883616b90c0	5	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
2788	628	sysmon64.exe	0x988361632080	14	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
2836	628	svchost.exe	0x988361631080	3	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
2880	628	WmiApSrv.exe	0x9883618de080	2	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
2948	628	svchost.exe	0x9883618dd080	6	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
2968	628	svchost.exe	0x9883618dc080	2	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
1596	628	windows_export	0x9883618d9080	13	-	0	False	2023-04-28 04:50:12.000000 	N/A	Disabled
3288	628	svchost.exe	0x9883618d5080	6	-	0	False	2023-04-28 04:50:13.000000 	N/A	Disabled
3524	3080	EC2Launch.exe	0x9883618d4080	0	-	0	False	2023-04-28 04:50:15.000000 	2023-04-28 04:50:50.000000 	Disabled
3548	752	unsecapp.exe	0x9883618d1080	3	-	0	False	2023-04-28 04:50:15.000000 	N/A	Disabled
3568	2588	ssm-agent-work	0x988361ec3080	11	-	0	False	2023-04-28 04:50:20.000000 	N/A	Disabled
4184	3568	conhost.exe	0x988361ec70c0	4	-	0	False	2023-04-28 04:50:21.000000 	N/A	Disabled
4236	628	svchost.exe	0x988361ba1080	1	-	0	False	2023-04-28 04:50:21.000000 	N/A	Disabled
4988	628	svchost.exe	0x9883624020c0	4	-	0	False	2023-04-28 04:52:24.000000 	N/A	Disabled
2808	628	svchost.exe	0x9883624540c0	23	-	0	False	2023-04-28 04:52:24.000000 	N/A	Disabled
4916	628	msdtc.exe	0x9883616bb080	9	-	0	False	2023-04-28 04:52:26.000000 	N/A	Disabled
3308	628	svchost.exe	0x9883616c4080	9	-	0	False	2023-04-28 04:52:28.000000 	N/A	Disabled
3300	628	svchost.exe	0x98835c4ba080	7	-	0	False	2023-04-28 04:52:31.000000 	N/A	Disabled
5116	628	svchost.exe	0x988361df1080	4	-	0	False	2023-04-28 06:13:04.000000 	N/A	Disabled
3612	628	svchost.exe	0x9883616bf080	10	-	0	False	2023-04-28 06:13:09.000000 	N/A	Disabled
1000	628	winlogbeat.exe	0x988362406080	18	-	0	False	2023-04-28 06:56:19.000000 	N/A	Disabled
1456	628	svchost.exe	0x98835c4ec080	5	-	0	False	2023-04-28 15:05:12.000000 	N/A	Disabled
2388	628	Velociraptor.e	0x98835c4f0080	12	-	0	False	2023-04-29 00:45:26.000000 	N/A	Disabled
4300	628	svchost.exe	0x98835c504080	1	-	0	False	2023-04-29 01:59:37.000000 	N/A	Disabled
3856	628	SecurityHealth	0x9883616c2080	26	-	0	False	2023-04-29 04:50:24.000000 	N/A	Disabled
4996	3808	csrss.exe	0x98835c50b080	10	-	2	False	2023-04-29 16:20:20.000000 	N/A	Disabled
4408	3808	winlogon.exe	0x98835c4f4080	2	-	2	False	2023-04-29 16:20:20.000000 	N/A	Disabled
2084	4408	fontdrvhost.ex	0x988361758080	5	-	2	False	2023-04-29 16:20:21.000000 	N/A	Disabled
1004	4408	dwm.exe	0x98835c529080	16	-	2	False	2023-04-29 16:20:21.000000 	N/A	Disabled
1012	416	rdpclip.exe	0x9883632a60c0	6	-	2	False	2023-04-29 16:20:32.000000 	N/A	Disabled
712	2668	sihost.exe	0x9883638c2080	10	-	2	False	2023-04-29 16:20:33.000000 	N/A	Disabled
3852	628	svchost.exe	0x9883634e0080	3	-	2	False	2023-04-29 16:20:33.000000 	N/A	Disabled
3256	628	svchost.exe	0x988363cd1080	2	-	2	False	2023-04-29 16:20:33.000000 	N/A	Disabled
2712	1804	taskhostw.exe	0x988362580140	5	-	2	False	2023-04-29 16:20:33.000000 	N/A	Disabled
4304	628	svchost.exe	0x988362b53380	5	-	0	False	2023-04-29 16:20:34.000000 	N/A	Disabled
3680	628	svchost.exe	0x988362595340	7	-	0	False	2023-04-29 16:20:34.000000 	N/A	Disabled
204	628	svchost.exe	0x98836245a080	6	-	0	False	2023-04-29 16:20:35.000000 	N/A	Disabled
2500	4304	ctfmon.exe	0x988363916380	8	-	2	False	2023-04-29 16:20:37.000000 	N/A	Disabled
964	4408	userinit.exe	0x988363cc7080	0	-	2	False	2023-04-29 16:20:43.000000 	2023-04-29 16:20:59.000000 	Disabled
600	964	explorer.exe	0x988363bda080	64	-	2	False	2023-04-29 16:20:43.000000 	N/A	Disabled
5820	5768	msedge.exe	0x9883634de080	0	-	2	False	2023-04-29 16:20:58.000000 	2023-04-29 16:21:20.000000 	Disabled
5744	752	TextInputHost.	0x9883632c0080	10	-	2	False	2023-04-29 16:21:12.000000 	N/A	Disabled
5816	752	StartMenuExper	0x988364da2380	8	-	2	False	2023-04-29 16:21:12.000000 	N/A	Disabled
3276	752	RuntimeBroker.	0x988364d90080	6	-	2	False	2023-04-29 16:21:15.000000 	N/A	Disabled
6268	752	SearchApp.exe	0x98836311b080	30	-	2	False	2023-04-29 16:21:17.000000 	N/A	Disabled
6304	752	RuntimeBroker.	0x98836311a080	6	-	2	False	2023-04-29 16:21:18.000000 	N/A	Disabled
6952	752	RuntimeBroker.	0x9883620c8080	1	-	2	False	2023-04-29 16:21:29.000000 	N/A	Disabled
5304	628	svchost.exe	0x9883632bd080	3	-	2	False	2023-04-29 16:22:33.000000 	N/A	Disabled
764	600	thunderbird.ex	0x988361629080	142	-	2	False	2023-04-29 16:29:26.000000 	N/A	Disabled
4904	764	thunderbird.ex	0x988363763080	5	-	2	False	2023-04-29 16:29:32.000000 	N/A	Disabled
4576	764	thunderbird.ex	0x988362b17380	14	-	2	False	2023-04-29 16:29:32.000000 	N/A	Disabled
6996	1804	taskhostw.exe	0x988361768080	3	-	2	False	2023-04-29 16:32:31.000000 	N/A	Disabled
2480	764	helper.exe	0x9883611c2080	0	-	2	True	2023-04-29 16:41:03.000000 	2023-04-29 16:41:04.000000 	Disabled
3752	628	svchost.exe	0x9883639bd080	5	-	0	False	2023-04-29 16:50:12.000000 	N/A	Disabled
7904	752	ApplicationFra	0x9883657d6080	2	-	2	False	2023-04-29 17:13:04.000000 	N/A	Disabled
9204	752	dllhost.exe	0x9883657f3080	6	-	2	False	2023-04-29 17:13:55.000000 	N/A	Disabled
8988	628	svchost.exe	0x988362b80080	1	-	0	False	2023-04-29 17:17:15.000000 	N/A	Disabled
6784	4016	csrss.exe	0x9883636e8080	10	-	3	False	2023-04-29 18:43:49.000000 	N/A	Disabled
7936	4016	winlogon.exe	0x988362cec080	2	-	3	False	2023-04-29 18:43:49.000000 	N/A	Disabled
5372	7936	fontdrvhost.ex	0x9883655e8080	5	-	3	False	2023-04-29 18:43:49.000000 	N/A	Disabled
8100	7936	dwm.exe	0x98835c693080	15	-	3	False	2023-04-29 18:43:49.000000 	N/A	Disabled
6184	416	rdpclip.exe	0x988364de1080	6	-	3	False	2023-04-29 18:43:53.000000 	N/A	Disabled
8964	2668	sihost.exe	0x98836a17a080	11	-	3	False	2023-04-29 18:43:53.000000 	N/A	Disabled
8032	628	svchost.exe	0x98836a17b080	3	-	3	False	2023-04-29 18:43:53.000000 	N/A	Disabled
6872	628	svchost.exe	0x988365c60080	4	-	3	False	2023-04-29 18:43:53.000000 	N/A	Disabled
5048	1804	taskhostw.exe	0x9883656a1080	5	-	3	False	2023-04-29 18:43:54.000000 	N/A	Disabled
1252	7936	userinit.exe	0x988365796080	0	-	3	False	2023-04-29 18:43:56.000000 	2023-04-29 18:44:24.000000 	Disabled
8868	1252	explorer.exe	0x988368a4b080	32	-	3	False	2023-04-29 18:43:56.000000 	N/A	Disabled
10020	9988	msedge.exe	0x98836912f300	0	-	3	False	2023-04-29 18:44:09.000000 	2023-04-29 18:44:28.000000 	Disabled
9960	752	SearchApp.exe	0x98836ea04080	31	-	3	False	2023-04-29 18:44:19.000000 	N/A	Disabled
10148	752	RuntimeBroker.	0x988366b7f080	5	-	3	False	2023-04-29 18:44:20.000000 	N/A	Disabled
10564	628	svchost.exe	0x9883634aa080	3	-	3	False	2023-04-29 18:44:25.000000 	N/A	Disabled
10608	752	StartMenuExper	0x988366b7d080	10	-	3	False	2023-04-29 18:44:25.000000 	N/A	Disabled
10760	752	RuntimeBroker.	0x9883634c5300	4	-	3	False	2023-04-29 18:44:28.000000 	N/A	Disabled
10948	752	dllhost.exe	0x988366b69080	6	-	3	False	2023-04-29 18:44:29.000000 	N/A	Disabled
7492	4304	ctfmon.exe	0x9883640f4080	8	-	3	False	2023-04-29 18:44:35.000000 	N/A	Disabled
10944	752	TextInputHost.	0x988365cf4080	10	-	3	False	2023-04-29 18:44:37.000000 	N/A	Disabled
10292	8868	powershell.exe	0x9883685a0080	10	-	3	False	2023-04-29 18:44:43.000000 	N/A	Disabled
9548	10292	conhost.exe	0x98836ea09080	3	-	3	False	2023-04-29 18:44:43.000000 	N/A	Disabled
10084	752	RuntimeBroker.	0x988368a76080	3	-	3	False	2023-04-29 18:44:44.000000 	N/A	Disabled
9996	7936	LogonUI.exe	0x988366b48080	5	-	3	False	2023-04-29 18:47:00.000000 	N/A	Disabled
6636	7648	msedge.exe	0x988364dc3080	0	-	2	False	2023-04-29 19:39:34.000000 	2023-04-29 19:39:42.000000 	Disabled
9296	1028	msedge.exe	0x988363ff0080	0	-	2	False	2023-04-29 19:39:34.000000 	2023-04-29 19:39:44.000000 	Disabled
3368	10120	msedge.exe	0x988366a062c0	0	-	2	False	2023-04-29 19:39:37.000000 	2023-04-29 19:39:47.000000 	Disabled
9824	10120	msedge.exe	0x988366241080	0	-	2	False	2023-04-29 19:39:37.000000 	2023-04-29 19:39:47.000000 	Disabled
3712	7068	msedge.exe	0x9883645f10c0	0	-	2	False	2023-04-29 19:39:37.000000 	2023-04-29 19:40:11.000000 	Disabled
4960	752	ShellExperienc	0x98836a17c080	17	-	2	False	2023-04-29 20:39:53.000000 	N/A	Disabled
2232	752	RuntimeBroker.	0x9883657e9080	2	-	2	False	2023-04-29 20:39:56.000000 	N/A	Disabled
6012	752	SecHealthUI.ex	0x9883655f0080	29	-	2	False	2023-04-29 21:00:42.000000 	N/A	Disabled
8828	752	SecurityHealth	0x98836391f080	1	-	2	False	2023-04-29 21:00:44.000000 	N/A	Disabled
1352	752	SecurityHealth	0x98836278b080	1	-	2	False	2023-04-29 21:03:15.000000 	N/A	Disabled
9368	752	RuntimeBroker.	0x98835c527080	1	-	2	False	2023-04-29 21:03:27.000000 	N/A	Disabled
6408	752	SecurityHealth	0x98836569d080	1	-	2	False	2023-04-29 21:35:15.000000 	N/A	Disabled
5248	600	chrome.exe	0x9883655ed080	38	-	2	True	2023-04-29 22:18:30.000000 	N/A	Disabled
7824	5248	chrome.exe	0x988369d8b080	7	-	2	True	2023-04-29 22:18:30.000000 	N/A	Disabled
2116	5248	chrome.exe	0x98835c677080	12	-	2	True	2023-04-29 22:18:31.000000 	N/A	Disabled
8824	5248	chrome.exe	0x988361df2080	14	-	2	True	2023-04-29 22:18:31.000000 	N/A	Disabled
8548	5248	chrome.exe	0x988361952080	9	-	2	True	2023-04-29 22:18:31.000000 	N/A	Disabled
8684	5248	chrome.exe	0x9883662350c0	16	-	2	True	2023-04-29 22:18:42.000000 	N/A	Disabled
2236	5248	chrome.exe	0x98836357b080	14	-	2	True	2023-04-29 22:19:02.000000 	N/A	Disabled
10496	5248	chrome.exe	0x988362158080	14	-	2	True	2023-04-29 22:19:22.000000 	N/A	Disabled
6904	5248	chrome.exe	0x988363691080	14	-	2	True	2023-04-29 22:19:24.000000 	N/A	Disabled
7232	5248	chrome.exe	0x98836310b080	14	-	2	True	2023-04-29 22:30:24.000000 	N/A	Disabled
4472	4408	LogonUI.exe	0x988366b6b080	5	-	2	False	2023-04-29 22:34:44.000000 	N/A	Disabled
3448	628	MsMpEng.exe	0x988363685080	8	-	0	False	2023-06-14 05:23:04.000000 	N/A	Disabled
7576	11088	GoogleCrashHan	0x98835c4b9080	3	-	0	True	2023-06-15 20:51:41.000000 	N/A	Disabled
9408	11088	GoogleCrashHan	0x988361630080	3	-	0	False	2023-06-15 20:51:41.000000 	N/A	Disabled
7368	6720	csrss.exe	0x98835c544080	11	-	5	False	2023-06-17 06:09:59.000000 	N/A	Disabled
4280	6720	winlogon.exe	0x98835c518080	4	-	5	False	2023-06-17 06:09:59.000000 	N/A	Disabled
8220	628	WUDFHost.exe	0x988361869080	8	-	0	False	2023-06-17 06:09:59.000000 	N/A	Disabled
10788	4280	fontdrvhost.ex	0x988368ae1080	5	-	5	False	2023-06-17 06:09:59.000000 	N/A	Disabled
3808	4280	dwm.exe	0x988366a5d080	17	-	5	False	2023-06-17 06:10:00.000000 	N/A	Disabled
6928	416	rdpclip.exe	0x9883639d90c0	10	-	5	False	2023-06-17 06:10:05.000000 	N/A	Disabled
9488	2668	sihost.exe	0x988362b86080	12	-	5	False	2023-06-17 06:10:05.000000 	N/A	Disabled
7304	628	svchost.exe	0x9883685aa080	5	-	5	False	2023-06-17 06:10:05.000000 	N/A	Disabled
6660	628	svchost.exe	0x988365c61080	5	-	5	False	2023-06-17 06:10:05.000000 	N/A	Disabled
2024	1804	taskhostw.exe	0x9883625f1080	6	-	5	False	2023-06-17 06:10:05.000000 	N/A	Disabled
5448	4280	userinit.exe	0x988361dc3080	0	-	5	False	2023-06-17 06:10:15.000000 	2023-06-17 06:10:31.000000 	Disabled
7100	1804	explorer.exe	0x98836857f080	61	-	5	False	2023-06-17 06:10:16.000000 	N/A	Disabled
5204	628	svchost.exe	0x9883634a9080	34	-	0	False	2023-06-17 06:10:16.000000 	N/A	Disabled
9436	628	svchost.exe	0x988363be3080	11	-	0	False	2023-06-17 06:10:17.000000 	N/A	Disabled
9684	628	svchost.exe	0x988361b60080	2	-	0	False	2023-06-17 06:10:18.000000 	N/A	Disabled
276	752	smartscreen.ex	0x988364bee080	10	-	5	False	2023-06-17 06:10:19.000000 	N/A	Disabled
5796	628	svchost.exe	0x98835c625080	3	-	0	False	2023-06-17 06:10:20.000000 	N/A	Disabled
9400	628	svchost.exe	0x988362aee080	7	-	0	False	2023-06-17 06:10:21.000000 	N/A	Disabled
3032	752	StartMenuExper	0x9883646f1080	23	-	5	False	2023-06-17 06:10:35.000000 	N/A	Disabled
10868	752	RuntimeBroker.	0x988363bee080	10	-	5	False	2023-06-17 06:10:36.000000 	N/A	Disabled
6484	752	SearchApp.exe	0x98836ed17080	18	-	5	False	2023-06-17 06:10:37.000000 	N/A	Disabled
6848	752	RuntimeBroker.	0x98836ed6a080	7	-	5	False	2023-06-17 06:10:37.000000 	N/A	Disabled
5424	4304	ctfmon.exe	0x98836a1e3080	10	-	5	False	2023-06-17 06:10:40.000000 	N/A	Disabled
7772	752	RuntimeBroker.	0x98836ed5a080	4	-	5	False	2023-06-17 06:10:46.000000 	N/A	Disabled
4744	752	TextInputHost.	0x9883657f9080	12	-	5	False	2023-06-17 06:11:20.000000 	N/A	Disabled
10288	628	svchost.exe	0x988361d0c080	5	-	5	False	2023-06-17 06:12:05.000000 	N/A	Disabled
5928	7100	WinTriage2023.	0x988362fdb080	21	-	5	False	2023-06-17 06:12:25.000000 	N/A	Disabled
3212	5928	conhost.exe	0x9883657f5080	6	-	5	False	2023-06-17 06:12:25.000000 	N/A	Disabled
6092	752	WmiPrvSE.exe	0x988361827080	12	-	0	False	2023-06-17 06:12:28.000000 	N/A	Disabled
6992	628	VSSVC.exe	0x988366243080	9	-	0	False	2023-06-17 06:12:28.000000 	N/A	Disabled
8652	628	svchost.exe	0x98835caae080	9	-	0	False	2023-06-17 06:12:28.000000 	N/A	Disabled
7256	5928	tmp819287859.e	0x988364dcf080	3	-	5	False	2023-06-17 06:12:28.000000 	N/A	Disabled
0	167690116130232		0x988369d7e080	0	-	-	False	N/A	N/A	Disabled
```

### PSTree
```
❯ vol -f PhysicalMemory.raw windows.pstree
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime

420	412	csrss.exe	0x9883602e4140	10	-	0	False	2023-04-28 04:50:06.000000 	N/A
492	412	wininit.exe	0x988360387140	2	-	0	False	2023-04-28 04:50:07.000000 	N/A
* 640	492	lsass.exe	0x988360385140	10	-	0	False	2023-04-28 04:50:07.000000 	N/A
* 784	492	fontdrvhost.ex	0x98836100b300	5	-	0	False	2023-04-28 04:50:08.000000 	N/A
* 628	492	services.exe	0x9883603df180	9	-	0	False	2023-04-28 04:50:07.000000 	N/A
** 6660	628	svchost.exe	0x988365c61080	5	-	5	False	2023-06-17 06:10:05.000000 	N/A
** 2572	628	svchost.exe	0x9883616c1080	15	-	0	False	2023-04-28 04:50:11.000000 	N/A
** 2588	628	amazon-ssm-age	0x9883616c0080	12	-	0	False	2023-04-28 04:50:11.000000 	N/A
*** 3568	2588	ssm-agent-work	0x988361ec3080	11	-	0	False	2023-04-28 04:50:20.000000 	N/A
**** 4184	3568	conhost.exe	0x988361ec70c0	4	-	0	False	2023-04-28 04:50:21.000000 	N/A
** 3612	628	svchost.exe	0x9883616bf080	10	-	0	False	2023-04-28 06:13:09.000000 	N/A
** 8220	628	WUDFHost.exe	0x988361869080	8	-	0	False	2023-06-17 06:09:59.000000 	N/A
** 10288	628	svchost.exe	0x988361d0c080	5	-	5	False	2023-06-17 06:12:05.000000 	N/A
** 2612	628	svchost.exe	0x9883616be080	7	-	0	False	2023-04-28 04:50:11.000000 	N/A
** 1596	628	windows_export	0x9883618d9080	13	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 1092	628	svchost.exe	0x98836124c080	7	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 2124	628	svchost.exe	0x98835c50e080	5	-	0	False	2023-04-28 04:50:11.000000 	N/A
** 5204	628	svchost.exe	0x9883634a9080	34	-	0	False	2023-06-17 06:10:16.000000 	N/A
** 2136	628	svchost.exe	0x98835c4f5080	4	-	0	False	2023-04-28 04:50:11.000000 	N/A
** 3680	628	svchost.exe	0x988362595340	7	-	0	False	2023-04-29 16:20:34.000000 	N/A
** 2668	628	svchost.exe	0x9883616bd080	7	-	0	False	2023-04-28 04:50:12.000000 	N/A
*** 712	2668	sihost.exe	0x9883638c2080	10	-	2	False	2023-04-29 16:20:33.000000 	N/A
*** 9488	2668	sihost.exe	0x988362b86080	12	-	5	False	2023-06-17 06:10:05.000000 	N/A
*** 8964	2668	sihost.exe	0x98836a17a080	11	-	3	False	2023-04-29 18:43:53.000000 	N/A
** 1140	628	svchost.exe	0x9883612883c0	12	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 1668	628	svchost.exe	0x98836148f340	6	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 7304	628	svchost.exe	0x9883685aa080	5	-	5	False	2023-06-17 06:10:05.000000 	N/A
** 4236	628	svchost.exe	0x988361ba1080	1	-	0	False	2023-04-28 04:50:21.000000 	N/A
** 1172	628	svchost.exe	0x9883612a03c0	2	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 1180	628	svchost.exe	0x98836162c080	3	-	0	False	2023-04-28 04:50:11.000000 	N/A
** 5796	628	svchost.exe	0x98835c625080	3	-	0	False	2023-06-17 06:10:20.000000 	N/A
** 3752	628	svchost.exe	0x9883639bd080	5	-	0	False	2023-04-29 16:50:12.000000 	N/A
** 1196	628	svchost.exe	0x9883612a6080	12	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 3256	628	svchost.exe	0x988363cd1080	2	-	2	False	2023-04-29 16:20:33.000000 	N/A
** 5304	628	svchost.exe	0x9883632bd080	3	-	2	False	2023-04-29 16:22:33.000000 	N/A
** 9400	628	svchost.exe	0x988362aee080	7	-	0	False	2023-06-17 06:10:21.000000 	N/A
** 700	628	svchost.exe	0x9883611ce340	4	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 2748	628	svchost.exe	0x9883616ba080	4	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 1736	628	svchost.exe	0x988361499340	4	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 4300	628	svchost.exe	0x98835c504080	1	-	0	False	2023-04-29 01:59:37.000000 	N/A
** 204	628	svchost.exe	0x98836245a080	6	-	0	False	2023-04-29 16:20:35.000000 	N/A
** 4304	628	svchost.exe	0x988362b53380	5	-	0	False	2023-04-29 16:20:34.000000 	N/A
*** 5424	4304	ctfmon.exe	0x98836a1e3080	10	-	5	False	2023-06-17 06:10:40.000000 	N/A
*** 2500	4304	ctfmon.exe	0x988363916380	8	-	2	False	2023-04-29 16:20:37.000000 	N/A
*** 7492	4304	ctfmon.exe	0x9883640f4080	8	-	3	False	2023-04-29 18:44:35.000000 	N/A
** 2776	628	svchost.exe	0x9883616b90c0	5	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 3288	628	svchost.exe	0x9883618d5080	6	-	0	False	2023-04-28 04:50:13.000000 	N/A
** 6872	628	svchost.exe	0x988365c60080	4	-	3	False	2023-04-29 18:43:53.000000 	N/A
** 9436	628	svchost.exe	0x988363be3080	11	-	0	False	2023-06-17 06:10:17.000000 	N/A
** 2788	628	sysmon64.exe	0x988361632080	14	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 3300	628	svchost.exe	0x98835c4ba080	7	-	0	False	2023-04-28 04:52:31.000000 	N/A
** 3308	628	svchost.exe	0x9883616c4080	9	-	0	False	2023-04-28 04:52:28.000000 	N/A
** 752	628	svchost.exe	0x988361071300	22	-	0	False	2023-04-28 04:50:08.000000 	N/A
*** 8828	752	SecurityHealth	0x98836391f080	1	-	2	False	2023-04-29 21:00:44.000000 	N/A
*** 10760	752	RuntimeBroker.	0x9883634c5300	4	-	3	False	2023-04-29 18:44:28.000000 	N/A
*** 6408	752	SecurityHealth	0x98836569d080	1	-	2	False	2023-04-29 21:35:15.000000 	N/A
*** 4744	752	TextInputHost.	0x9883657f9080	12	-	5	False	2023-06-17 06:11:20.000000 	N/A
*** 276	752	smartscreen.ex	0x988364bee080	10	-	5	False	2023-06-17 06:10:19.000000 	N/A
*** 9368	752	RuntimeBroker.	0x98835c527080	1	-	2	False	2023-04-29 21:03:27.000000 	N/A
*** 6304	752	RuntimeBroker.	0x98836311a080	6	-	2	False	2023-04-29 16:21:18.000000 	N/A
*** 10148	752	RuntimeBroker.	0x988366b7f080	5	-	3	False	2023-04-29 18:44:20.000000 	N/A
*** 6952	752	RuntimeBroker.	0x9883620c8080	1	-	2	False	2023-04-29 16:21:29.000000 	N/A
*** 6268	752	SearchApp.exe	0x98836311b080	30	-	2	False	2023-04-29 16:21:17.000000 	N/A
*** 5816	752	StartMenuExper	0x988364da2380	8	-	2	False	2023-04-29 16:21:12.000000 	N/A
*** 2232	752	RuntimeBroker.	0x9883657e9080	2	-	2	False	2023-04-29 20:39:56.000000 	N/A
*** 10944	752	TextInputHost.	0x988365cf4080	10	-	3	False	2023-04-29 18:44:37.000000 	N/A
*** 6848	752	RuntimeBroker.	0x98836ed6a080	7	-	5	False	2023-06-17 06:10:37.000000 	N/A
*** 10948	752	dllhost.exe	0x988366b69080	6	-	3	False	2023-04-29 18:44:29.000000 	N/A
*** 1352	752	SecurityHealth	0x98836278b080	1	-	2	False	2023-04-29 21:03:15.000000 	N/A
*** 3276	752	RuntimeBroker.	0x988364d90080	6	-	2	False	2023-04-29 16:21:15.000000 	N/A
*** 6092	752	WmiPrvSE.exe	0x988361827080	12	-	0	False	2023-06-17 06:12:28.000000 	N/A
*** 6484	752	SearchApp.exe	0x98836ed17080	18	-	5	False	2023-06-17 06:10:37.000000 	N/A
*** 3032	752	StartMenuExper	0x9883646f1080	23	-	5	False	2023-06-17 06:10:35.000000 	N/A
*** 3548	752	unsecapp.exe	0x9883618d1080	3	-	0	False	2023-04-28 04:50:15.000000 	N/A
*** 7772	752	RuntimeBroker.	0x98836ed5a080	4	-	5	False	2023-06-17 06:10:46.000000 	N/A
*** 7904	752	ApplicationFra	0x9883657d6080	2	-	2	False	2023-04-29 17:13:04.000000 	N/A
*** 4960	752	ShellExperienc	0x98836a17c080	17	-	2	False	2023-04-29 20:39:53.000000 	N/A
*** 10084	752	RuntimeBroker.	0x988368a76080	3	-	3	False	2023-04-29 18:44:44.000000 	N/A
*** 9960	752	SearchApp.exe	0x98836ea04080	31	-	3	False	2023-04-29 18:44:19.000000 	N/A
*** 5744	752	TextInputHost.	0x9883632c0080	10	-	2	False	2023-04-29 16:21:12.000000 	N/A
*** 10608	752	StartMenuExper	0x988366b7d080	10	-	3	False	2023-04-29 18:44:25.000000 	N/A
*** 9204	752	dllhost.exe	0x9883657f3080	6	-	2	False	2023-04-29 17:13:55.000000 	N/A
*** 10868	752	RuntimeBroker.	0x988363bee080	10	-	5	False	2023-06-17 06:10:36.000000 	N/A
*** 6012	752	SecHealthUI.ex	0x9883655f0080	29	-	2	False	2023-04-29 21:00:42.000000 	N/A
** 2808	628	svchost.exe	0x9883624540c0	23	-	0	False	2023-04-28 04:52:24.000000 	N/A
** 2296	628	svchost.exe	0x98836162e080	6	-	0	False	2023-04-28 04:50:11.000000 	N/A
** 776	628	svchost.exe	0x9883611cc0c0	3	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 1804	628	svchost.exe	0x9883614ed340	13	-	0	False	2023-04-28 04:50:10.000000 	N/A
*** 2024	1804	taskhostw.exe	0x9883625f1080	6	-	5	False	2023-06-17 06:10:05.000000 	N/A
*** 6996	1804	taskhostw.exe	0x988361768080	3	-	2	False	2023-04-29 16:32:31.000000 	N/A
*** 5048	1804	taskhostw.exe	0x9883656a1080	5	-	3	False	2023-04-29 18:43:54.000000 	N/A
*** 2712	1804	taskhostw.exe	0x988362580140	5	-	2	False	2023-04-29 16:20:33.000000 	N/A
*** 7100	1804	explorer.exe	0x98836857f080	61	-	5	False	2023-06-17 06:10:16.000000 	N/A
**** 5928	7100	WinTriage2023.	0x988362fdb080	21	-	5	False	2023-06-17 06:12:25.000000 	N/A
***** 7256	5928	tmp819287859.e	0x988364dcf080	3	-	5	False	2023-06-17 06:12:28.000000 	N/A
***** 3212	5928	conhost.exe	0x9883657f5080	6	-	5	False	2023-06-17 06:12:25.000000 	N/A
** 3852	628	svchost.exe	0x9883634e0080	3	-	2	False	2023-04-29 16:20:33.000000 	N/A
** 3856	628	SecurityHealth	0x9883616c2080	26	-	0	False	2023-04-29 04:50:24.000000 	N/A
** 2836	628	svchost.exe	0x988361631080	3	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 1816	628	svchost.exe	0x9883615020c0	2	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 8988	628	svchost.exe	0x988362b80080	1	-	0	False	2023-04-29 17:17:15.000000 	N/A
** 1832	628	svchost.exe	0x98836150d3c0	7	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 1844	628	svchost.exe	0x9883615153c0	3	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 4916	628	msdtc.exe	0x9883616bb080	9	-	0	False	2023-04-28 04:52:26.000000 	N/A
** 1852	628	svchost.exe	0x988361519080	5	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 2880	628	WmiApSrv.exe	0x9883618de080	2	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 10564	628	svchost.exe	0x9883634aa080	3	-	3	False	2023-04-29 18:44:25.000000 	N/A
** 6992	628	VSSVC.exe	0x988366243080	9	-	0	False	2023-06-17 06:12:28.000000 	N/A
** 1364	628	svchost.exe	0x988361329380	6	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 2388	628	Velociraptor.e	0x98835c4f0080	12	-	0	False	2023-04-29 00:45:26.000000 	N/A
** 1884	628	svchost.exe	0x9883615763c0	7	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 864	628	svchost.exe	0x9883610c3380	15	-	0	False	2023-04-28 04:50:08.000000 	N/A
** 8032	628	svchost.exe	0x98836a17b080	3	-	3	False	2023-04-29 18:43:53.000000 	N/A
** 1384	628	svchost.exe	0x9883613273c0	5	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 880	628	svchost.exe	0x9883611d03c0	4	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 1392	628	svchost.exe	0x98836131d340	9	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 3448	628	MsMpEng.exe	0x988363685080	8	-	0	False	2023-06-14 05:23:04.000000 	N/A
** 4988	628	svchost.exe	0x9883624020c0	4	-	0	False	2023-04-28 04:52:24.000000 	N/A
** 2948	628	svchost.exe	0x9883618dd080	6	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 1420	628	svchost.exe	0x98836138d340	3	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 2448	628	spoolsv.exe	0x9883616c5080	9	-	0	False	2023-04-28 04:50:11.000000 	N/A
** 916	628	svchost.exe	0x98836112b340	5	-	0	False	2023-04-28 04:50:08.000000 	N/A
** 2968	628	svchost.exe	0x9883618dc080	2	-	0	False	2023-04-28 04:50:12.000000 	N/A
** 416	628	svchost.exe	0x9883611a43c0	37	-	0	False	2023-04-28 04:50:09.000000 	N/A
*** 6184	416	rdpclip.exe	0x988364de1080	6	-	3	False	2023-04-29 18:43:53.000000 	N/A
*** 6928	416	rdpclip.exe	0x9883639d90c0	10	-	5	False	2023-06-17 06:10:05.000000 	N/A
*** 1012	416	rdpclip.exe	0x9883632a60c0	6	-	2	False	2023-04-29 16:20:32.000000 	N/A
** 1444	628	svchost.exe	0x9883613a43c0	9	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 1956	628	svchost.exe	0x9883615ae340	3	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 1456	628	svchost.exe	0x98835c4ec080	5	-	0	False	2023-04-28 15:05:12.000000 	N/A
** 1460	628	svchost.exe	0x9883613a93c0	13	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 1476	628	svchost.exe	0x9883613ab340	3	-	0	False	2023-04-28 04:50:10.000000 	N/A
** 8652	628	svchost.exe	0x98835caae080	9	-	0	False	2023-06-17 06:12:28.000000 	N/A
** 9684	628	svchost.exe	0x988361b60080	2	-	0	False	2023-06-17 06:10:18.000000 	N/A
** 988	628	svchost.exe	0x9883611cd080	1	-	0	False	2023-04-28 04:50:09.000000 	N/A
** 1000	628	winlogbeat.exe	0x988362406080	18	-	0	False	2023-04-28 06:56:19.000000 	N/A
** 5116	628	svchost.exe	0x988361df1080	4	-	0	False	2023-04-28 06:13:04.000000 	N/A
500	484	csrss.exe	0x98836038a080	9	-	1	False	2023-04-28 04:50:07.000000 	N/A
560	484	winlogon.exe	0x9883603c7080	2	-	1	False	2023-04-28 04:50:07.000000 	N/A
* 992	560	LogonUI.exe	0x988361154180	9	-	1	False	2023-04-28 04:50:08.000000 	N/A
* 780	560	fontdrvhost.ex	0x98836107a280	5	-	1	False	2023-04-28 04:50:08.000000 	N/A
* 1020	560	dwm.exe	0x988361190100	17	-	1	False	2023-04-28 04:50:09.000000 	N/A
3524	3080	EC2Launch.exe	0x9883618d4080	0	-	0	False	2023-04-28 04:50:15.000000 	2023-04-28 04:50:50.000000
5820	5768	msedge.exe	0x9883634de080	0	-	2	False	2023-04-29 16:20:58.000000 	2023-04-29 16:21:20.000000
6784	4016	csrss.exe	0x9883636e8080	10	-	3	False	2023-04-29 18:43:49.000000 	N/A
7936	4016	winlogon.exe	0x988362cec080	2	-	3	False	2023-04-29 18:43:49.000000 	N/A
* 8100	7936	dwm.exe	0x98835c693080	15	-	3	False	2023-04-29 18:43:49.000000 	N/A
* 5372	7936	fontdrvhost.ex	0x9883655e8080	5	-	3	False	2023-04-29 18:43:49.000000 	N/A
* 9996	7936	LogonUI.exe	0x988366b48080	5	-	3	False	2023-04-29 18:47:00.000000 	N/A
* 1252	7936	userinit.exe	0x988365796080	0	-	3	False	2023-04-29 18:43:56.000000 	2023-04-29 18:44:24.000000
** 8868	1252	explorer.exe	0x988368a4b080	32	-	3	False	2023-04-29 18:43:56.000000 	N/A
*** 10292	8868	powershell.exe	0x9883685a0080	10	-	3	False	2023-04-29 18:44:43.000000 	N/A
**** 9548	10292	conhost.exe	0x98836ea09080	3	-	3	False	2023-04-29 18:44:43.000000 	N/A
10020	9988	msedge.exe	0x98836912f300	0	-	3	False	2023-04-29 18:44:09.000000 	2023-04-29 18:44:28.000000
6636	7648	msedge.exe	0x988364dc3080	0	-	2	False	2023-04-29 19:39:34.000000 	2023-04-29 19:39:42.000000
9296	1028	msedge.exe	0x988363ff0080	0	-	2	False	2023-04-29 19:39:34.000000 	2023-04-29 19:39:44.000000
3368	10120	msedge.exe	0x988366a062c0	0	-	2	False	2023-04-29 19:39:37.000000 	2023-04-29 19:39:47.000000
9824	10120	msedge.exe	0x988366241080	0	-	2	False	2023-04-29 19:39:37.000000 	2023-04-29 19:39:47.000000
3712	7068	msedge.exe	0x9883645f10c0	0	-	2	False	2023-04-29 19:39:37.000000 	2023-04-29 19:40:11.000000
7576	11088	GoogleCrashHan	0x98835c4b9080	3	-	0	True	2023-06-15 20:51:41.000000 	N/A
9408	11088	GoogleCrashHan	0x988361630080	3	-	0	False	2023-06-15 20:51:41.000000 	N/A
7368	6720	csrss.exe	0x98835c544080	11	-	5	False	2023-06-17 06:09:59.000000 	N/A
4280	6720	winlogon.exe	0x98835c518080	4	-	5	False	2023-06-17 06:09:59.000000 	N/A
* 3808	4280	dwm.exe	0x988366a5d080	17	-	5	False	2023-06-17 06:10:00.000000 	N/A
** 4408	3808	winlogon.exe	0x98835c4f4080	2	-	2	False	2023-04-29 16:20:20.000000 	N/A
*** 4472	4408	LogonUI.exe	0x988366b6b080	5	-	2	False	2023-04-29 22:34:44.000000 	N/A
*** 964	4408	userinit.exe	0x988363cc7080	0	-	2	False	2023-04-29 16:20:43.000000 	2023-04-29 16:20:59.000000
**** 600	964	explorer.exe	0x988363bda080	64	-	2	False	2023-04-29 16:20:43.000000 	N/A
***** 5248	600	chrome.exe	0x9883655ed080	38	-	2	True	2023-04-29 22:18:30.000000 	N/A
****** 10496	5248	chrome.exe	0x988362158080	14	-	2	True	2023-04-29 22:19:22.000000 	N/A
****** 7232	5248	chrome.exe	0x98836310b080	14	-	2	True	2023-04-29 22:30:24.000000 	N/A
****** 8548	5248	chrome.exe	0x988361952080	9	-	2	True	2023-04-29 22:18:31.000000 	N/A
****** 2116	5248	chrome.exe	0x98835c677080	12	-	2	True	2023-04-29 22:18:31.000000 	N/A
****** 8684	5248	chrome.exe	0x9883662350c0	16	-	2	True	2023-04-29 22:18:42.000000 	N/A
****** 7824	5248	chrome.exe	0x988369d8b080	7	-	2	True	2023-04-29 22:18:30.000000 	N/A
****** 6904	5248	chrome.exe	0x988363691080	14	-	2	True	2023-04-29 22:19:24.000000 	N/A
****** 8824	5248	chrome.exe	0x988361df2080	14	-	2	True	2023-04-29 22:18:31.000000 	N/A
****** 2236	5248	chrome.exe	0x98836357b080	14	-	2	True	2023-04-29 22:19:02.000000 	N/A
***** 764	600	thunderbird.ex	0x988361629080	142	-	2	False	2023-04-29 16:29:26.000000 	N/A
****** 4904	764	thunderbird.ex	0x988363763080	5	-	2	False	2023-04-29 16:29:32.000000 	N/A
****** 4576	764	thunderbird.ex	0x988362b17380	14	-	2	False	2023-04-29 16:29:32.000000 	N/A
****** 2480	764	helper.exe	0x9883611c2080	0	-	2	True	2023-04-29 16:41:03.000000 	2023-04-29 16:41:04.000000
*** 2084	4408	fontdrvhost.ex	0x988361758080	5	-	2	False	2023-04-29 16:20:21.000000 	N/A
*** 1004	4408	dwm.exe	0x98835c529080	16	-	2	False	2023-04-29 16:20:21.000000 	N/A
** 4996	3808	csrss.exe	0x98835c50b080	10	-	2	False	2023-04-29 16:20:20.000000 	N/A
* 5448	4280	userinit.exe	0x988361dc3080	0	-	5	False	2023-06-17 06:10:15.000000 	2023-06-17 06:10:31.000000
* 10788	4280	fontdrvhost.ex	0x988368ae1080	5	-	5	False	2023-06-17 06:09:59.000000 	N/A
0	167690116130232		0x988369d7e080	0	-	-	False	N/A	N/A
* 4	0	System	0x98835c481040	143	-	N/A	False	2023-04-28 04:50:04.000000 	N/A
** 96	4	Registry	0x98835c5c8040	4	-	N/A	False	2023-04-28 04:50:02.000000 	N/A
** 308	4	smss.exe	0x98835ce50040	2	-	N/A	False	2023-04-28 04:50:04.000000 	N/A
```

### Netscan
```
❯ vol -f PhysicalMemory.raw windows.netscan
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished
Offset	Proto	LocalAddr	LocalPort	ForeignAddr	ForeignPort	State	PID	Owner	Created

0x98835c4c1470	TCPv4	0.0.0.0	49669	0.0.0.0	0	LISTENING	640	lsass.exe	2023-04-28 04:50:11.000000
0x98835c4c1470	TCPv6	::	49669	::	0	LISTENING	640	lsass.exe	2023-04-28 04:50:11.000000
0x98835c4c1730	TCPv4	0.0.0.0	49670	0.0.0.0	0	LISTENING	2124	svchost.exe	2023-04-28 04:50:11.000000
0x98835c4c1890	TCPv4	0.0.0.0	49686	0.0.0.0	0	LISTENING	1804	svchost.exe	2023-04-28 04:50:11.000000
0x98835c4c1b50	TCPv4	0.0.0.0	49690	0.0.0.0	0	LISTENING	2448	spoolsv.exe	2023-04-28 04:50:12.000000
0x98835c4c1b50	TCPv6	::	49690	::	0	LISTENING	2448	spoolsv.exe	2023-04-28 04:50:12.000000
0x98835c4c1cb0	TCPv4	0.0.0.0	49670	0.0.0.0	0	LISTENING	2124	svchost.exe	2023-04-28 04:50:11.000000
0x98835c4c1cb0	TCPv6	::	49670	::	0	LISTENING	2124	svchost.exe	2023-04-28 04:50:11.000000
0x98835c8931b0	TCPv4	0.0.0.0	135	0.0.0.0	0	LISTENING	864	svchost.exe	2023-04-28 04:50:08.000000
0x98835c893310	TCPv4	0.0.0.0	135	0.0.0.0	0	LISTENING	864	svchost.exe	2023-04-28 04:50:08.000000
0x98835c893310	TCPv6	::	135	::	0	LISTENING	864	svchost.exe	2023-04-28 04:50:08.000000
0x98835c893470	TCPv4	0.0.0.0	49665	0.0.0.0	0	LISTENING	492	wininit.exe	2023-04-28 04:50:08.000000
0x98835c8935d0	TCPv4	0.0.0.0	49664	0.0.0.0	0	LISTENING	640	lsass.exe	2023-04-28 04:50:08.000000
0x98835c8935d0	TCPv6	::	49664	::	0	LISTENING	640	lsass.exe	2023-04-28 04:50:08.000000
0x98835c893730	TCPv4	0.0.0.0	49665	0.0.0.0	0	LISTENING	492	wininit.exe	2023-04-28 04:50:08.000000
0x98835c893730	TCPv6	::	49665	::	0	LISTENING	492	wininit.exe	2023-04-28 04:50:08.000000
0x98835c894650	TCPv4	0.0.0.0	49664	0.0.0.0	0	LISTENING	640	lsass.exe	2023-04-28 04:50:08.000000
0x98836125b010	UDPv4	0.0.0.0	0	*	0		880	svchost.exe	2023-04-28 04:50:09.000000
0x98836125b010	UDPv6	::	0	*	0		880	svchost.exe	2023-04-28 04:50:09.000000
0x98836125caa0	UDPv4	0.0.0.0	0	*	0		880	svchost.exe	2023-04-28 04:50:09.000000
0x988361277e30	UDPv4	172.16.50.146	137	*	0		4	System	2023-04-28 04:50:09.000000
0x9883612782e0	UDPv4	172.16.50.146	138	*	0		4	System	2023-04-28 04:50:09.000000
0x988361278920	UDPv4	0.0.0.0	0	*	0		1140	svchost.exe	2023-04-28 04:50:10.000000
0x988361278920	UDPv6	::	0	*	0		1140	svchost.exe	2023-04-28 04:50:10.000000
0x988361279be0	UDPv4	0.0.0.0	3389	*	0		416	svchost.exe	2023-04-28 04:50:10.000000
0x9883612fe050	TCPv4	172.16.50.146	139	0.0.0.0	0	LISTENING	4	System	2023-04-28 04:50:09.000000
0x9883612fe5d0	TCPv4	0.0.0.0	3389	0.0.0.0	0	LISTENING	416	svchost.exe	2023-04-28 04:50:10.000000
0x9883612fe5d0	TCPv6	::	3389	::	0	LISTENING	416	svchost.exe	2023-04-28 04:50:10.000000
0x9883612fe730	TCPv4	0.0.0.0	49666	0.0.0.0	0	LISTENING	1196	svchost.exe	2023-04-28 04:50:10.000000
0x9883612fe890	TCPv4	0.0.0.0	49666	0.0.0.0	0	LISTENING	1196	svchost.exe	2023-04-28 04:50:10.000000
0x9883612fe890	TCPv6	::	49666	::	0	LISTENING	1196	svchost.exe	2023-04-28 04:50:10.000000
0x9883612feb50	TCPv4	0.0.0.0	3389	0.0.0.0	0	LISTENING	416	svchost.exe	2023-04-28 04:50:10.000000
0x9883612fee10	TCPv4	0.0.0.0	49686	0.0.0.0	0	LISTENING	1804	svchost.exe	2023-04-28 04:50:11.000000
0x9883612fee10	TCPv6	::	49686	::	0	LISTENING	1804	svchost.exe	2023-04-28 04:50:11.000000
0x9883612ff4f0	TCPv4	0.0.0.0	49669	0.0.0.0	0	LISTENING	640	lsass.exe	2023-04-28 04:50:11.000000
0x9883612ff650	TCPv4	0.0.0.0	49690	0.0.0.0	0	LISTENING	2448	spoolsv.exe	2023-04-28 04:50:12.000000
0x9883613b4d80	UDPv4	0.0.0.0	3389	*	0		416	svchost.exe	2023-04-28 04:50:10.000000
0x9883613b4d80	UDPv6	::	3389	*	0		416	svchost.exe	2023-04-28 04:50:10.000000
0x9883613b6040	UDPv4	0.0.0.0	5353	*	0		1140	svchost.exe	2023-04-28 04:50:10.000000
0x9883613b6040	UDPv6	::	5353	*	0		1140	svchost.exe	2023-04-28 04:50:10.000000
0x9883613b6680	UDPv4	0.0.0.0	5353	*	0		1140	svchost.exe	2023-04-28 04:50:10.000000
0x98836156aae0	UDPv4	127.0.0.1	59465	*	0		1384	svchost.exe	2023-04-28 04:50:11.000000
0x988361638b90	UDPv4	127.0.0.1	59467	*	0		1852	svchost.exe	2023-04-28 04:50:11.000000
0x9883616ec540	UDPv4	0.0.0.0	0	*	0		640	lsass.exe	2023-04-28 04:50:11.000000
0x9883616ec540	UDPv6	::	0	*	0		640	lsass.exe	2023-04-28 04:50:11.000000
0x9883616ed350	UDPv4	0.0.0.0	0	*	0		640	lsass.exe	2023-04-28 04:50:11.000000
0x9883616edcb0	UDPv4	0.0.0.0	0	*	0		640	lsass.exe	2023-04-28 04:50:11.000000
0x9883616ede40	UDPv4	0.0.0.0	0	*	0		640	lsass.exe	2023-04-28 04:50:11.000000
0x9883616ede40	UDPv6	::	0	*	0		640	lsass.exe	2023-04-28 04:50:11.000000
0x9883616f14f0	UDPv4	127.0.0.1	59469	*	0		640	lsass.exe	2023-04-28 04:50:11.000000
0x9883616fe1b0	TCPv4	0.0.0.0	47001	0.0.0.0	0	LISTENING	4	System	2023-04-28 04:50:14.000000
0x9883616fe1b0	TCPv6	::	47001	::	0	LISTENING	4	System	2023-04-28 04:50:14.000000
0x9883616fe890	TCPv4	0.0.0.0	445	0.0.0.0	0	LISTENING	4	System	2023-04-28 04:50:13.000000
0x9883616fe890	TCPv6	::	445	::	0	LISTENING	4	System	2023-04-28 04:50:13.000000
0x9883616ff4f0	TCPv4	0.0.0.0	5986	0.0.0.0	0	LISTENING	4	System	2023-04-28 04:50:14.000000
0x9883616ff4f0	TCPv6	::	5986	::	0	LISTENING	4	System	2023-04-28 04:50:14.000000
0x9883616ffa70	TCPv4	0.0.0.0	5985	0.0.0.0	0	LISTENING	4	System	2023-04-28 04:50:14.000000
0x9883616ffa70	TCPv6	::	5985	::	0	LISTENING	4	System	2023-04-28 04:50:14.000000
0x988361a4b740	UDPv4	127.0.0.1	56648	*	0		1392	svchost.exe	2023-04-28 04:50:13.000000
0x988361a538f0	UDPv4	0.0.0.0	0	*	0		3288	svchost.exe	2023-04-28 04:50:14.000000
0x988361a55060	UDPv4	0.0.0.0	0	*	0		3288	svchost.exe	2023-04-28 04:50:14.000000
0x988361a55060	UDPv6	::	0	*	0		3288	svchost.exe	2023-04-28 04:50:14.000000
0x988361c255d0	TCPv4	0.0.0.0	49723	0.0.0.0	0	LISTENING	628	services.exe	2023-04-28 04:50:23.000000
0x988361c26650	TCPv4	0.0.0.0	49723	0.0.0.0	0	LISTENING	628	services.exe	2023-04-28 04:50:23.000000
0x988361c26650	TCPv6	::	49723	::	0	LISTENING	628	services.exe	2023-04-28 04:50:23.000000
0x988361c26d30	TCPv4	0.0.0.0	9100	0.0.0.0	0	LISTENING	1596	windows_export	2023-04-28 04:50:31.000000
0x988361c26d30	TCPv6	::	9100	::	0	LISTENING	1596	windows_export	2023-04-28 04:50:31.000000
0x988361e69780	UDPv4	0.0.0.0	55092	*	0		1140	svchost.exe	2023-06-16 09:05:18.000000
0x988361e69780	UDPv6	::	55092	*	0		1140	svchost.exe	2023-06-16 09:05:18.000000
0x988361e6bb70	UDPv4	0.0.0.0	123	*	0		880	svchost.exe	2023-06-16 14:01:59.000000
0x988361e6bb70	UDPv6	::	123	*	0		880	svchost.exe	2023-06-16 14:01:59.000000
0x988361e6d600	UDPv4	0.0.0.0	123	*	0		880	svchost.exe	2023-06-16 14:01:59.000000
0x988361e717a0	UDPv4	127.0.0.1	61860	*	0		600	explorer.exe	2023-04-29 18:38:40.000000
0x988361f040b0	UDPv4	0.0.0.0	5355	*	0		1140	svchost.exe	2023-06-17 05:50:55.000000
0x988361f040b0	UDPv6	::	5355	*	0		1140	svchost.exe	2023-06-17 05:50:55.000000
0x988361f043d0	UDPv4	0.0.0.0	5355	*	0		1140	svchost.exe	2023-06-17 05:50:55.000000
0x988361f26e80	UDPv4	172.16.50.146	62535	*	0		5248	chrome.exe	2023-06-16 02:29:28.000000
0x988363d5c940	UDPv4	0.0.0.0	5353	*	0		5248	chrome.exe	2023-04-29 22:18:37.000000
0x988363d5cad0	UDPv4	0.0.0.0	5353	*	0		5248	chrome.exe	2023-04-29 22:18:37.000000
0x988363d5cad0	UDPv6	::	5353	*	0		5248	chrome.exe	2023-04-29 22:18:37.000000
0x988363fb91e0	UDPv4	0.0.0.0	0	*	0		5928	WinTriage2023.	2023-06-17 06:12:29.000000
0x988363fb91e0	UDPv6	::	0	*	0		5928	WinTriage2023.	2023-06-17 06:12:29.000000
0x988363fbb120	UDPv4	0.0.0.0	59736	*	0		1140	svchost.exe	2023-06-17 06:10:21.000000
0x988363fbb120	UDPv6	::	59736	*	0		1140	svchost.exe	2023-06-17 06:10:21.000000
0x9883641437b0	UDPv4	0.0.0.0	63771	*	0		1140	svchost.exe	2023-05-22 04:51:23.000000
0x9883641437b0	UDPv6	::	63771	*	0		1140	svchost.exe	2023-05-22 04:51:23.000000
0x988364346500	UDPv4	0.0.0.0	123	*	0		880	svchost.exe	2023-06-17 03:26:34.000000
0x988364346500	UDPv6	::	123	*	0		880	svchost.exe	2023-06-17 03:26:34.000000
0x98836434ab50	UDPv4	0.0.0.0	123	*	0		880	svchost.exe	2023-06-17 03:26:34.000000
0x98836468c640	UDPv4	0.0.0.0	52029	*	0		1140	svchost.exe	2023-06-16 16:36:54.000000
0x98836468c640	UDPv6	::	52029	*	0		1140	svchost.exe	2023-06-16 16:36:54.000000
0x98836480de80	UDPv4	127.0.0.1	51069	*	0		2612	svchost.exe	2023-04-30 03:57:42.000000
0x988366324600	UDPv4	127.0.0.1	62479	*	0		2296	svchost.exe	2023-05-28 04:50:31.000000
0xe760000b0650	TCPv4	0.0.0.0	49723	0.0.0.0	0	LISTENING	628	services.exe	2023-04-28 04:50:23.000000
0xe760000b0650	TCPv6	::	49723	::	0	LISTENING	628	services.exe	2023-04-28 04:50:23.000000
0xe760000b0d30	TCPv4	0.0.0.0	9100	0.0.0.0	0	LISTENING	1596	windows_export	2023-04-28 04:50:31.000000
0xe760000b0d30	TCPv6	::	9100	::	0	LISTENING	1596	windows_export	2023-04-28 04:50:31.000000
0xe760000b15d0	TCPv4	0.0.0.0	49723	0.0.0.0	0	LISTENING	628	services.exe	2023-04-28 04:50:23.000000
```

### Malfind

```
❯ vol -f PhysicalMemory.raw windows.malfind
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished
PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Hexdump	Disasm

10292	powershell.exe	0x23e6e140000	0x23e6e14cfff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled
00 00 00 00 00 00 00 00	........
90 78 dc 6d 3e 02 00 00	.x.m>...
90 78 dc 6d 3e 02 00 00	.x.m>...
00 00 dc 6d 3e 02 00 00	...m>...
e0 0d 14 6e 3e 02 00 00	...n>...
00 10 14 6e 3e 02 00 00	...n>...
00 d0 14 6e 3e 02 00 00	...n>...
01 00 00 00 00 00 00 00	........
0x23e6e140000:	add	byte ptr [rax], al
0x23e6e140002:	add	byte ptr [rax], al
0x23e6e140004:	add	byte ptr [rax], al
0x23e6e140006:	add	byte ptr [rax], al
0x23e6e140008:	nop
0x23e6e140009:	js	0x23e6e13ffe7
0x23e6e14000b:	insd	dword ptr [rdi], dx
0x23e6e14000c:	add	al, byte ptr ds:[rax]
0x23e6e14000f:	add	byte ptr [rax + 0x3e6ddc78], dl
0x23e6e140015:	add	al, byte ptr [rax]
0x23e6e140017:	add	byte ptr [rax], al
0x23e6e140019:	add	ah, bl
0x23e6e14001b:	insd	dword ptr [rdi], dx
0x23e6e14001c:	add	al, byte ptr ds:[rax]
0x23e6e14001f:	add	al, ah
0x23e6e140021:	or	eax, 0x23e6e14
0x23e6e140026:	add	byte ptr [rax], al
0x23e6e140028:	add	byte ptr [rax], dl
0x23e6e14002a:	adc	al, 0x6e
0x23e6e14002c:	add	al, byte ptr ds:[rax]
0x23e6e14002f:	add	byte ptr [rax], al
0x23e6e140031:	rcl	byte ptr [rsi + rbp*2], 1
0x23e6e140034:	add	al, byte ptr ds:[rax]
0x23e6e140037:	add	byte ptr [rcx], al
0x23e6e140039:	add	byte ptr [rax], al
0x23e6e14003b:	add	byte ptr [rax], al
0x23e6e14003d:	add	byte ptr [rax], al
10292	powershell.exe	0x7df4662c0000	0x7df46635ffff	VadS	PAGE_EXECUTE_READWRITE	2	1	Disabled
d8 ff ff ff ff ff ff ff	........
08 00 00 00 00 00 00 00	........
01 00 00 00 00 00 00 00	........
00 02 0e 03 38 00 00 00	....8...
68 01 d7 07 45 00 00 00	h...E...
d8 5d 24 e5 f8 7f 00 00	.]$.....
00 10 22 e5 f8 7f 00 00	..".....
08 4a 3b e5 f8 7f 00 00	.J;.....
0x7df4662c0000:	fdivr	st(7)
10292	powershell.exe	0x7df4662b0000	0x7df4662bffff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled
00 00 00 00 00 00 00 00	........
78 0d 00 00 00 00 00 00	x.......
45 00 00 00 49 c7 c2 00	E...I...
00 00 00 48 b8 d0 49 82	...H..I.
e6 f8 7f 00 00 ff e0 49	.......I
c7 c2 01 00 00 00 48 b8	......H.
d0 49 82 e6 f8 7f 00 00	.I......
ff e0 49 c7 c2 02 00 00	..I.....
0x7df4662b0000:	add	byte ptr [rax], al
0x7df4662b0002:	add	byte ptr [rax], al
0x7df4662b0004:	add	byte ptr [rax], al
0x7df4662b0006:	add	byte ptr [rax], al
0x7df4662b0008:	js	0x7df4662b0017
0x7df4662b000a:	add	byte ptr [rax], al
0x7df4662b000c:	add	byte ptr [rax], al
0x7df4662b000e:	add	byte ptr [rax], al
0x7df4662b0010:	add	byte ptr [r8], r8b
0x7df4662b0013:	add	byte ptr [rcx - 0x39], cl
0x7df4662b0016:	ret	0
0x7df4662b0019:	add	byte ptr [rax], al
0x7df4662b001b:	movabs	rax, 0x7ff8e68249d0
0x7df4662b0025:	jmp	rax
0x7df4662b0027:	mov	r10, 1
0x7df4662b002e:	movabs	rax, 0x7ff8e68249d0
0x7df4662b0038:	jmp	rax
3448	MsMpEng.exe	0x25449400000	0x254494fffff	VadS	PAGE_EXECUTE_READWRITE	256	1	Disabled
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
0x25449400000:	add	byte ptr [rax], al
0x25449400002:	add	byte ptr [rax], al
0x25449400004:	add	byte ptr [rax], al
0x25449400006:	add	byte ptr [rax], al
0x25449400008:	add	byte ptr [rax], al
0x2544940000a:	add	byte ptr [rax], al
0x2544940000c:	add	byte ptr [rax], al
0x2544940000e:	add	byte ptr [rax], al
0x25449400010:	add	byte ptr [rax], al
0x25449400012:	add	byte ptr [rax], al
0x25449400014:	add	byte ptr [rax], al
0x25449400016:	add	byte ptr [rax], al
0x25449400018:	add	byte ptr [rax], al
0x2544940001a:	add	byte ptr [rax], al
0x2544940001c:	add	byte ptr [rax], al
0x2544940001e:	add	byte ptr [rax], al
0x25449400020:	add	byte ptr [rax], al
0x25449400022:	add	byte ptr [rax], al
0x25449400024:	add	byte ptr [rax], al
0x25449400026:	add	byte ptr [rax], al
0x25449400028:	add	byte ptr [rax], al
0x2544940002a:	add	byte ptr [rax], al
0x2544940002c:	add	byte ptr [rax], al
0x2544940002e:	add	byte ptr [rax], al
0x25449400030:	add	byte ptr [rax], al
0x25449400032:	add	byte ptr [rax], al
0x25449400034:	add	byte ptr [rax], al
0x25449400036:	add	byte ptr [rax], al
0x25449400038:	add	byte ptr [rax], al
0x2544940003a:	add	byte ptr [rax], al
0x2544940003c:	add	byte ptr [rax], al
0x2544940003e:	add	byte ptr [rax], al
3448	MsMpEng.exe	0x25449800000	0x254499fffff	VadS	PAGE_EXECUTE_READWRITE	512	1	Disabled
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
0x25449800000:	add	byte ptr [rax], al
0x25449800002:	add	byte ptr [rax], al
0x25449800004:	add	byte ptr [rax], al
0x25449800006:	add	byte ptr [rax], al
0x25449800008:	add	byte ptr [rax], al
0x2544980000a:	add	byte ptr [rax], al
0x2544980000c:	add	byte ptr [rax], al
0x2544980000e:	add	byte ptr [rax], al
0x25449800010:	add	byte ptr [rax], al
0x25449800012:	add	byte ptr [rax], al
0x25449800014:	add	byte ptr [rax], al
0x25449800016:	add	byte ptr [rax], al
0x25449800018:	add	byte ptr [rax], al
0x2544980001a:	add	byte ptr [rax], al
0x2544980001c:	add	byte ptr [rax], al
0x2544980001e:	add	byte ptr [rax], al
0x25449800020:	add	byte ptr [rax], al
0x25449800022:	add	byte ptr [rax], al
0x25449800024:	add	byte ptr [rax], al
0x25449800026:	add	byte ptr [rax], al
0x25449800028:	add	byte ptr [rax], al
0x2544980002a:	add	byte ptr [rax], al
0x2544980002c:	add	byte ptr [rax], al
0x2544980002e:	add	byte ptr [rax], al
0x25449800030:	add	byte ptr [rax], al
0x25449800032:	add	byte ptr [rax], al
0x25449800034:	add	byte ptr [rax], al
0x25449800036:	add	byte ptr [rax], al
0x25449800038:	add	byte ptr [rax], al
0x2544980003a:	add	byte ptr [rax], al
0x2544980003c:	add	byte ptr [rax], al
0x2544980003e:	add	byte ptr [rax], al
276	smartscreen.ex	0x2255d540000	0x2255d55ffff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled
48 89 54 24 10 48 89 4c	H.T$.H.L
24 08 4c 89 44 24 18 4c	$.L.D$.L
89 4c 24 20 48 8b 41 28	.L$.H.A(
48 8b 48 08 48 8b 51 50	H.H.H.QP
48 83 e2 f8 48 8b ca 48	H...H..H
b8 60 00 54 5d 25 02 00	.`.T]%..
00 48 2b c8 48 81 f9 70	.H+.H..p
0f 00 00 76 09 48 c7 c1	...v.H..
0x2255d540000:	mov	qword ptr [rsp + 0x10], rdx
0x2255d540005:	mov	qword ptr [rsp + 8], rcx
0x2255d54000a:	mov	qword ptr [rsp + 0x18], r8
0x2255d54000f:	mov	qword ptr [rsp + 0x20], r9
0x2255d540014:	mov	rax, qword ptr [rcx + 0x28]
0x2255d540018:	mov	rcx, qword ptr [rax + 8]
0x2255d54001c:	mov	rdx, qword ptr [rcx + 0x50]
0x2255d540020:	and	rdx, 0xfffffffffffffff8
0x2255d540024:	mov	rcx, rdx
0x2255d540027:	movabs	rax, 0x2255d540060
0x2255d540031:	sub	rcx, rax
0x2255d540034:	cmp	rcx, 0xf70
0x2255d54003b:	jbe	0x2255d540046
276	smartscreen.ex	0x2255dd30000	0x2255dd4ffff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled
48 89 54 24 10 48 89 4c	H.T$.H.L
24 08 4c 89 44 24 18 4c	$.L.D$.L
89 4c 24 20 48 8b 41 28	.L$.H.A(
48 8b 48 08 48 8b 51 50	H.H.H.QP
48 83 e2 f8 48 8b ca 48	H...H..H
b8 60 00 d3 5d 25 02 00	.`..]%..
00 48 2b c8 48 81 f9 70	.H+.H..p
0f 00 00 76 09 48 c7 c1	...v.H..
0x2255dd30000:	mov	qword ptr [rsp + 0x10], rdx
0x2255dd30005:	mov	qword ptr [rsp + 8], rcx
0x2255dd3000a:	mov	qword ptr [rsp + 0x18], r8
0x2255dd3000f:	mov	qword ptr [rsp + 0x20], r9
0x2255dd30014:	mov	rax, qword ptr [rcx + 0x28]
0x2255dd30018:	mov	rcx, qword ptr [rax + 8]
0x2255dd3001c:	mov	rdx, qword ptr [rcx + 0x50]
0x2255dd30020:	and	rdx, 0xfffffffffffffff8
0x2255dd30024:	mov	rcx, rdx
0x2255dd30027:	movabs	rax, 0x2255dd30060
0x2255dd30031:	sub	rcx, rax
0x2255dd30034:	cmp	rcx, 0xf70
0x2255dd3003b:	jbe	0x2255dd30046
```

---
### References
