### Why did I make a section on this alone? 
The most important thing that an analyst can do is review the system logs. The Windows Event logs has great details that's important to heed.

** NOTE:** Sysmon is missing. There is a lot of data and that will take a day in itself.


**Considerations**  
* Threat actors are known to clear the typical Security, System, and Application  
* Best to have supplementary logs if you can help it

## Windows Event Logs Involved

| Log Name | Enabled by Default? |
|----------|---------------------|
| Security | Yes |
| System | Yes| 
| Sysmon| No |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational| No |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin| No |
| Microsoft-Windows-TerminalServices-RDPClient/Operational| No |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational| No |
| | |

### Planning Considerations
* Sysmon is very noisy   
* Care should be taken when enabling RDP logs, tied to mstsc.exe.  

## Activity Mapping

### 21:29 UTC - Initial Access into IoT-ENG-WKST
**Microsoft-Windows-Sysmon/Operation** - Significant details, enough to stand on its own, but very unlikely to be common place

**Security** 
* 4672: Special privileges assigned to new logon 
* 4648: Logon was attempted using explicit credentials
	* Account Whose Credentials were used: Account Name: seth.morgan; Network Information: Network Adress: 172.16.40.100
* 4624: Successful Logon  
	* Logon Information: Logon Type: 10 / New Logon: Account Name: seth.morgan; Account Domain: MAGNUMTEMPUS / Network Information: 172.16.40.100


**System** - Supplementary Only, not enough to stand on its own
* 10016: The application-specific permission settings do not grant Local Launch permissio for the COM Server application with CLSID  {21B896BF-008D-4D01-A27B-26061B960DD7}  and APPID {03E09F3B-DCE4-44FE-A9CF-82D050827E1C}  to the user MAGNUMTEMPUS\seth.morgan SID (S-1-5-21-2369732838-3797832421-459094119-1170) from address LocalHost (Using LRPC) running in the application container Unavailable SID (Unavailable). This security permission can be modified using the Component Services administrative tool.
* 7036: The AppX Deployment Service (AppXSVC) service entered the running state.
* 16: The access history in hive ``\??\C:\Users\seth.morgan\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\Settings\settings.dat`` was cleared updating 3 keys and creating 1 modified pages.

**Application** - Supplementary
* 5: Windows Search Service ha created default configuration for new user '``MAGNUMTEMPUS\seth.morgan``'

**Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational** - IP address and timezone
* 131: Server accepted a new TCP connection fron client 172.16.40.100:60822
* 104: Client timezone is [-5] hour from UTC;

**Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational** - Stands out on its own
* EventID 1149: User authentication succeeded: User: seth.morgan / Domain: / Source Network Address: 172.16.40.100

**Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin** - Supplement
* EventID 1158 - Remote Desktop Service accepted a connection from IP address 172.16.10.93

**Microsoft-Windows-TerminalServices-LocalSessionManager/Operational** - Stands out
* 41: Begin session arbitration: User: MAGNUMTEMPUS\seth.morgan; Session ID: 3
* 21: Remote Desktop Services: Session logon succeeded: User: MAGNUMTEMPUS\seth.morgan; Session ID: 3; Source Network Address: 172.16.40.100
* 22: Remote Desktop Services: Shell start notification received



### Activities In-Between
**Microsoft-Windows-Sysmon/Operational**
* 21:36 UTC: Found Organization email lists.
	* ``"C:\Windows\system32\NOTEPAD.EXE" \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\2022-Backup\2022-Backup\org email list.txt \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\2022-Backup\2022-Backup\``
* 21:36 UTC: Found opened up passwords from Jason's private folders
	* ``"C:\Program Files (x86)\OpenOffice 4\program\\scalc.exe" -o "\\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Jason's Private Folder\passwords.xls" \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Jason's Private Folder\
* 21:37 UTC: Opened up the RigNotes
	* ``"C:\Program Files (x86)\OpenOffice 4\program\\scalc.exe" -o "\\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Tombstone-Copy\Rig_Notes.xlsx" \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Tombstone-Copy\``
* 21:39 UTC: EventID 7: Downloading nmap7.93-setup.exe ``
	* SHA1=61ADFA25CBD51375F0355AA9B895E1DC28389E19
	* MD5=17C877FEC39FC8CE03B7F012EF25211F
	* SHA256= DBB0173BB09D64CA716B3FD9EFB0222ECC7C13C11978D29F2B61CF550BCD7ABA
* 21:40 UTC: EventID 1: Execution of Nmap scan for an open RDP connection
	* nmap  172.16.60.0/24 -p 3389 -Pn -v
* 21:45 UTC: EventID 1: Opened files from the restored Internal Department's Share Folder
	* ``"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\2022-Backup\2022-Backup\Internal\Depts\Operations\are-you-ready-guide.pdf \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\2022-Backup\2022-Backup\Internal\Depts\Operations\``
* 21:49 UTC: EventID 1: Found credentialsfor the Tombstone
	* ``"C:\Windows\system32\NOTEPAD.EXE" \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software\admin.txt \\172.16.50.146\Users\seth.morgan\Downloads\NEWSHARE2023\Tombstone-Copy\Software\``
* 21:49 UTC: EventID 12, 3: Started up mstsc.exe (Remote Desktop Connection)
	* 172.16.50.20:54708 -> 172.16.60.19:3389



### 21:49 UTC - Lateral Movement into iot-Jumpbox 
**Microsoft-Windows-TerminalServices-RDPClient/Operational** - Stands out
* 1024 - RDP ClientActiveX is trying to connect to server (172.16.60.19)
* 1029 - Base64(SHA256(UserName)) is = omDUw7DU8fTIDIjScBzBMBeDoZd5gZW3JEQTMdPMjcM=-
* 1027 - Connected to domain (IOT-JUMPBOX) with session 1

**Security**
* 4648 - Logon was attempt using explicit credentials
	* Account Whose credentials were used: Account Name: iotadmin; Account Domain: MAGNUM TEMPUS / Target Server; Target Server Name: iot-jumpbox


### 22:01 UTC - Exiting iot-Jumpbox 
**Microsoft-Windows-TerminalServices-RDPClient/Operational** - Sands out
* 1105 - The multi-transport connection has been disconnected.
* 1026 - RDP ClientActiveX has been disconnected (Reason= 1)
	* Window Close.




### Egress Activities
**Microsoft-Windows-Sysmon/Operational**
* 22:01 UTC: EventID 11: Deleted nmap.exe
	* ``C:\$Recycle.Bin\S-1-5-21-2369732838-3797832421-459094119-1170\$INE424N.exe``

### 22:02 UTC - Exiting IoT-ENG-WKST

**Security**
* 4634: An account was logged off

**Microsoft-Windows-TerminalServices-LocalSessionManager/Operational** - Stands out
* 39: Session 5 has been disconnected by session 5
* 40: Session 5 has been disconnected, reason code 11
* 24: Remote Desktop Services: Session has disconnected: User: ``MAGNUMTEMPUS\seth.morgan`` ; Session ID: 5; Source Network Address: 172.16.40.100

**Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational** - Supplement
* 148: The channels was closed between the server and the client (many channels have this EventID)



## REFERENCE:
* [Gathering RDP event logs from Windows 10 machines (4292509)](https://support.oneidentity.com/one-identity-safeguard-for-privileged-sessions/kb/4292509/gathering-rdp-event-logs-from-windows-10-machines)
* [Hatena Blog - Microsoft-Windows-TerminalServices-RDPClient and NLA](https://port139.hatenablog.com/entry/2019/05/03/162705)
* [Null Security - Windows RDP-Related Event Logs: The Client Side of the Story](https://nullsec.us/windows-rdp-related-event-logs-the-client-side-of-the-story/)
* [List of Sysmon Event IDs for Threat Hunting](https://systemweakness.com/list-of-sysmon-event-ids-for-threat-hunting-4250b47cd567)

