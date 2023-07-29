# IaaS Linux Logs Review Template - Splunk
BTV Project Obsidian, 2023

Author: juju43, https://blueteamvillage.org/programs/project-obsidian/ https://discord.gg/blueteamvillage
<img align="right" width="100" height="100" src="https://cfc.blueteamvillage.org/media/call-for-content-2021/img/20200622_BTVillage_logos_RGB_pos_hcOC7Qx.png">

This playbook is to help validating available logs
It helps to baseline environment, identify gaps and control points.

It targets Defcon31 BlueTeamVillage Project obsidian environment and splunk platform but it can be adapt to other logging platforms.

Resources
* https://github.com/microsoft/msticpy/
* https://infosecjupyterthon.com/
* https://dropbox.tech/security/how-dropbox-security-builds-better-tools-for-threat-detection-and-incident-response
(Linux)
* https://github.com/Azure/Azure-Sentinel-Notebooks/blob/master/Entity%20Explorer%20-%20Linux%20Host.ipynb
* https://securitydatasets.com/notebooks/atomic/linux/intro.html
(Win)
* https://github.com/Azure/Azure-Sentinel-Notebooks/blob/master/Entity%20Explorer%20-%20Windows%20Host.ipynb
* https://github.com/OTRF/ThreatHunter-Playbook/tree/master/docs/hunts/windows
* https://securitydatasets.com/notebooks/atomic/windows/intro.html


## Findings

* new ssh key added (osquery pack_osquery-custom-pack_authorized_keys)
* change of server dns nameservers (osquery pack_osquery-custom-pack_dns_resolvers; removed but none added seen?)
* usage of kerbrute, crackmapexec, and more (sysmonforlinux process). missing part of process tree
* no fim traces (osquery; bug, misconfiguration, tampering or log ingestion issue?)
* python packages install traces through sysmonforlinux process but not osquery (pack_osquery-custom-pack_python_packages; bug, misconfiguration, tampering or log ingestion issue?)
* multiple services deactivation from systemd include sshd, systemd-resolved.
  * Careful! Here we can see filebeat collection via journald or via log file is not equivalent...
* fun fact: crackmapexec execution before tool install generated a call to `snap snap-advise --command crackmapexec`

## Table of Contents

* Import
* Configuration
* Queries
  * Authentication
    * fail
    * success
  * Remote access
  * Privilege escalation
  * Privileged users activities? root, Administrator...
  * Service activities
    * Time
    * Logging
    * Scheduled tasks
  * System boot, on/off
  * Process activities
  * Network activities
  * File Integrity Monitoring (FIM)
  * AV logs?
  * Misc

## Import


```python
# Check we are running Python 3.6
import sys
MIN_REQ_PYTHON = (3,6)
if sys.version_info < MIN_REQ_PYTHON:
    print('Check the Kernel->Change Kernel menu and ensure that Python 3.6')
    print('or later is selected as the active kernel.')
    sys.exit("Python %s.%s or later is required.\n" % MIN_REQ_PYTHON)
```


```python
# Imports
import pandas as pd
import msticpy.nbtools as nbtools
from datetime import datetime,timedelta
import os
```


```python
# path to config file
os.environ['MSTICPYCONFIG'] = '/home/ubuntu/msticpyconfig.yaml'
from msticpy.nbtools import *
from msticpy.data.data_providers import QueryProvider
from msticpy.common.wsconfig import WorkspaceConfig
from msticpy.nbtools.data_viewer import DataViewer
from msticpy.vis.matrix_plot import plot_matrix
from msticpy.nbtools import process_tree as ptree
print('Imports Complete')
```

    Imports Complete


## Configuration


```python
# Interactive settings edit
# https://msticpy.readthedocs.io/en/latest/getting_started/SettingsEditor.html#using-mpconfigfile-to-check-and-manage-your-msticpyconfig-yaml
from msticpy.config import MpConfigFile, MpConfigEdit, MpConfigControls
mpconfig = MpConfigFile()
# mpconfig.load_default()
# mpconfig.view_settings()
mpconfig
```


    VBox(children=(HTML(value='<h3>MSTICPy settings</h3>'), VBox(children=(VBox(children=(Label(value='Operations'…



```python
# q_times = nbwidgets.QueryTime(units='hours', max_before=72, before=1, max_after=0)
q_times = nbwidgets.QueryTime(origin_time=datetime(2023, 4, 29), units='days', max_before=3, before=1, max_after=0)
q_times.display()
```


    VBox(children=(HTML(value='<h4>Set query time boundaries</h4>'), HBox(children=(DatePicker(value=datetime.date…



```python
query_common_args = '''agent.name=ip-172-16-40-100 earliest="04/29/2023:01:00:00" latest="04/29/2023:23:00:00"'''
```


```python
# Configuration
# if free splunk, 
#  * enable the 'allowRemoteLogin' setting in your server.conf file - /opt/splunk/etc/system/local/server.conf
splunk_prov = QueryProvider('Splunk')
splunk_prov.connect()
```

    connected



```python
# pandas
pd.set_option('display.max_colwidth', 500)
```

## Queries

### Authentication


```python
splunk_query = f'''search index=linux su: {query_common_args}
| stats count by host,message'''
df_su = splunk_prov.exec_query(splunk_query)
df_su.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 94.27it/s]





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:54:34 ip-172-16-40-100 su: (to root) root on pts/1</td>
      <td>2</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:54:34 ip-172-16-40-100 su: pam_unix(su:session): session opened for user root(uid=0) by ubuntu(uid=0)</td>
      <td>2</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 22:04:24 ip-172-16-40-100 su: pam_unix(su:session): session closed for user root</td>
      <td>2</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>pam_unix(su:session): session opened for user root(uid=0) by ubuntu(uid=0)</td>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=linux session {query_common_args}
| stats count by host,message'''
df_session = splunk_prov.exec_query(splunk_query)
df_session.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 95.08it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/su</td>
      <td>4</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>ubuntu : problem with defaults entries ; TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ;</td>
      <td>2</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>ubuntu : unable to resolve host ip-172-16-40-100: Temporary failure in name resolution</td>
      <td>2</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>(root) CMD (   cd / &amp;&amp; run-parts --report /etc/cron.hourly)</td>
      <td>2</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>(to root) root on pts/1</td>
      <td>2</td>
    </tr>
    <tr>
      <th>5</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 18:17:01 ip-172-16-40-100 CRON[110709]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)</td>
      <td>2</td>
    </tr>
    <tr>
      <th>6</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:52:00 ip-172-16-40-100 sshd[111122]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)</td>
      <td>2</td>
    </tr>
    <tr>
      <th>7</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:52:00 ip-172-16-40-100 systemd-logind[533]: New session 50 of user ubuntu.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>8</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:52:00 ip-172-16-40-100 systemd: pam_unix(systemd-user:session): session opened for user ubuntu(uid=1000) by (uid=0)</td>
      <td>2</td>
    </tr>
    <tr>
      <th>9</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:52:00 ip-172-16-40-100 systemd[111125]: Listening on REST API socket for snapd user session agent.</td>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>



### Remote access


```python
splunk_query = f'''search index=linux sshd (accepted OR failed) {query_common_args}
| stats count by host,message'''
df_ssh = splunk_prov.exec_query(splunk_query)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.88it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python
df_ssh[['host', 'message']].head(10)
# df_ssh.head(10)
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>Accepted publickey for ubuntu from 18.220.210.56 port 32944 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>Accepted publickey for ubuntu from 18.220.210.56 port 32946 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>Accepted publickey for ubuntu from 18.220.210.56 port 34062 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>Accepted publickey for ubuntu from 18.220.210.56 port 40742 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>Accepted publickey for ubuntu from 18.220.210.56 port 45664 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>5</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:52:00 ip-172-16-40-100 sshd[111122]: Accepted publickey for ubuntu from 18.220.210.56 port 34062 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>6</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:54:24 ip-172-16-40-100 sshd[111240]: Accepted publickey for ubuntu from 18.220.210.56 port 40742 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>7</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 20:27:22 ip-172-16-40-100 sshd[113613]: Accepted publickey for ubuntu from 18.220.210.56 port 45664 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>8</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 20:27:45 ip-172-16-40-100 sshd[113674]: Accepted publickey for ubuntu from 18.220.210.56 port 32944 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
    <tr>
      <th>9</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 20:27:48 ip-172-16-40-100 sshd[113724]: Accepted publickey for ubuntu from 18.220.210.56 port 32946 ssh2: RSA SHA256:ld2khyX0DVEOUgAdZxTITd6k3Cggme5OFSjYNsUi5Ck</td>
    </tr>
  </tbody>
</table>
</div>




```python
# sshd[1234]: Starting session: subsystem 'sftp' for USER from 10.x.y.z port 55098 id 1
splunk_query = f'''search index=linux sshd subsystem {query_common_args}
| stats count by host,message'''
df_sftp = splunk_prov.exec_query(splunk_query)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 97.13it/s]

    Warning - query did not return any results.


    
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python

```


```python
splunk_query = f'''search index=osquery {query_common_args}
| spath input=message
| search name="pack_osquery-custom-pack_authorized_keys"'''
df_ssh_authorized_keys = splunk_prov.exec_query(splunk_query)
df_ssh_authorized_keys.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 94.26it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>_bkt</th>
      <th>_cd</th>
      <th>_indextime</th>
      <th>_raw</th>
      <th>_serial</th>
      <th>_si</th>
      <th>_sourcetype</th>
      <th>_subsecond</th>
      <th>_time</th>
      <th>agent.name</th>
      <th>...</th>
      <th>hostIdentifier</th>
      <th>index</th>
      <th>linecount</th>
      <th>message</th>
      <th>name</th>
      <th>numerics</th>
      <th>source</th>
      <th>sourcetype</th>
      <th>splunk_server</th>
      <th>unixTime</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>osquery~5~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>5:147689</td>
      <td>1682798112</td>
      <td>{"@timestamp":"2023-04-29T19:55:10.887Z","log":{"offset":5697816,"file":{"path":"/var/log/osquery/osqueryd.results.log"}},"message":"{\"name\":\"pack_osquery-custom-pack_authorized_keys\",\"hostIdentifier\":\"ip-172-16-40-100\",\"calendarTime\":\"Sat Apr 29 19:55:08 2023 UTC\",\"unixTime\":1682798108,\"epoch\":0,\"counter\":1,\"numerics\":false,\"decorations\":{\"host_uuid\":\"ec24eb0d-2f49-5eb4-da77-1878abd17af8\",\"username\":\"\"},\"columns\":{\"algorithm\":\"ssh-rsa\",\"comment\":\"\",\"...</td>
      <td>738</td>
      <td>[ip-172-16-22-20, osquery]</td>
      <td>osquery</td>
      <td>.887</td>
      <td>2023-04-29T19:55:10.887+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>...</td>
      <td>ip-172-16-40-100</td>
      <td>osquery</td>
      <td>1</td>
      <td>[{"name":"pack_osquery-custom-pack_authorized_keys","hostIdentifier":"ip-172-16-40-100","calendarTime":"Sat Apr 29 19:55:08 2023 UTC","unixTime":1682798108,"epoch":0,"counter":1,"numerics":false,"decorations":{"host_uuid":"ec24eb0d-2f49-5eb4-da77-1878abd17af8","username":""},"columns":{"algorithm":"ssh-rsa","comment":"","key":"AAAAB3NzaC1yc2EAAAADAQABAAACAQCqw5jYoWl9iajxA4JKKw7TtyMqQN+GltcOXL7DR3rPWYKJ32qKRi53t1zAKSVNwN8JmKE9EWTwOMRjq4F19SnsdjZhyGiZCKc2mzckWQN6bf2dcDfddUHgjswGLDzQkSYU0/Ks/Ew...</td>
      <td>pack_osquery-custom-pack_authorized_keys</td>
      <td>false</td>
      <td>osquery</td>
      <td>osquery</td>
      <td>ip-172-16-22-20</td>
      <td>1682798108</td>
    </tr>
  </tbody>
</table>
<p>1 rows × 28 columns</p>
</div>



### Privilege Escalation


```python
splunk_query = f'''search index=linux sudo {query_common_args}
| stats count by host,message'''
df_sudo = splunk_prov.exec_query(splunk_query)
df_sudo.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 94.01it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/su</td>
      <td>4</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>ubuntu : problem with defaults entries ; TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ;</td>
      <td>2</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>ubuntu : unable to resolve host ip-172-16-40-100: Temporary failure in name resolution</td>
      <td>2</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:52:35 ip-172-16-40-100 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/su</td>
      <td>2</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:54:34 ip-172-16-40-100 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/su</td>
      <td>2</td>
    </tr>
    <tr>
      <th>5</th>
      <td>ip-172-16-40-100</td>
      <td>Apr 29 19:54:34 ip-172-16-40-100 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)</td>
      <td>2</td>
    </tr>
    <tr>
      <th>6</th>
      <td>ip-172-16-40-100</td>
      <td>pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)</td>
      <td>4</td>
    </tr>
  </tbody>
</table>
</div>



### Services activities


```python
splunk_query = f'''search index=linux "journald.process.name"=systemd (start OR stop OR Deactivated) {query_common_args}
| stats count by host,message'''
df_services = splunk_prov.exec_query(splunk_query)
df_services.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 94.95it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>Closed D-Bus User Message Bus Socket.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent (ssh-agent emulation).</td>
      <td>6</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent and passphrase cache (access for web browsers).</td>
      <td>6</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent and passphrase cache (restricted).</td>
      <td>6</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent and passphrase cache.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>5</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG network certificate management daemon.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>6</th>
      <td>ip-172-16-40-100</td>
      <td>Closed REST API socket for snapd user session agent.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>7</th>
      <td>ip-172-16-40-100</td>
      <td>Closed debconf communication socket.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>8</th>
      <td>ip-172-16-40-100</td>
      <td>Created slice User Application Slice.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>9</th>
      <td>ip-172-16-40-100</td>
      <td>Created slice User Slice of UID 1000.</td>
      <td>6</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=linux "journald.process.name"=systemd (ntpd OR openntpd OR ntpdate OR rdate OR chrony) {query_common_args}
| stats count by host,message'''
df_service_time = splunk_prov.exec_query(splunk_query)
df_service_time.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 95.85it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>Started chrony, an NTP client/server.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>Starting chrony, an NTP client/server...</td>
      <td>2</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>Stopped chrony, an NTP client/server.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>Stopping chrony, an NTP client/server...</td>
      <td>2</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>chrony.service: Consumed 2.331s CPU time.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>5</th>
      <td>ip-172-16-40-100</td>
      <td>chrony.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=linux "journald.process.name"=systemd (journald OR rsyslog OR syslog-ng) {query_common_args}
| stats count by host,message'''
df_service_logging = splunk_prov.exec_query(splunk_query)
df_service_logging.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.78it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>Closed D-Bus User Message Bus Socket.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent (ssh-agent emulation).</td>
      <td>6</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent and passphrase cache (access for web browsers).</td>
      <td>6</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent and passphrase cache (restricted).</td>
      <td>6</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG cryptographic agent and passphrase cache.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>5</th>
      <td>ip-172-16-40-100</td>
      <td>Closed GnuPG network certificate management daemon.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>6</th>
      <td>ip-172-16-40-100</td>
      <td>Closed REST API socket for snapd user session agent.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>7</th>
      <td>ip-172-16-40-100</td>
      <td>Closed debconf communication socket.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>8</th>
      <td>ip-172-16-40-100</td>
      <td>Created slice User Application Slice.</td>
      <td>6</td>
    </tr>
    <tr>
      <th>9</th>
      <td>ip-172-16-40-100</td>
      <td>Created slice User Slice of UID 1000.</td>
      <td>6</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=linux "journald.process.name"=systemd (cron OR at OR systemd-timers) {query_common_args}
| stats count by host,message'''
df_service_scheduledtasks = splunk_prov.exec_query(splunk_query)
df_service_scheduledtasks.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.99it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>Started Regular background program processing daemon.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>Stopped Regular background program processing daemon.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>Stopping Regular background program processing daemon...</td>
      <td>2</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>cron.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>




```python

```


```python
splunk_query = f'''search index=linux "input.type"!=journald (start OR stop OR Deactivated) {query_common_args}
| stats count by host,agent.type,input.type,message'''
df_services2 = splunk_prov.exec_query(splunk_query)
df_services2.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.34it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>agent.type</th>
      <th>input.type</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 19:52:00 ip-172-16-40-100 systemd[111125]: Queued start job for default target Main User Target.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 19:54:24 ip-172-16-40-100 systemd[111243]: Queued start job for default target Main User Target.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:38 ip-172-16-40-100 systemd[1]: chrony.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:38 ip-172-16-40-100 systemd[1]: cron.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:38 ip-172-16-40-100 systemd[1]: irqbalance.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>5</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:38 ip-172-16-40-100 systemd[1]: polkit.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>6</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 PackageKit: daemon start</td>
      <td>2</td>
    </tr>
    <tr>
      <th>7</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 kernel: [131708.892459] systemd[1]: systemd-networkd-wait-online.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>8</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 kernel: [131708.920591] systemd[1]: systemd-resolved.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>9</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>log</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 kernel: [131708.950196] systemd[1]: ssh.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=linux "journald.process.name"=systemd systemd-resolved {query_common_args}
| stats count by host,agent.type,input.type,message'''
df_systemdresolved1 = splunk_prov.exec_query(splunk_query)
df_systemdresolved1.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 95.92it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>agent.type</th>
      <th>input.type</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>journald</td>
      <td>Starting Network Name Resolution...</td>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=linux systemd-resolved {query_common_args}
| stats count by host,agent.type,log.file.path,message'''
df_systemdresolved2 = splunk_prov.exec_query(splunk_query)
df_systemdresolved2.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 95.18it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>agent.type</th>
      <th>log.file.path</th>
      <th>message</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>/var/log/syslog</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 kernel: [131708.920591] systemd[1]: systemd-resolved.service: Deactivated successfully.</td>
      <td>2</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>/var/log/syslog</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 systemd-resolved[112854]: . IN DS 20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d</td>
      <td>2</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>/var/log/syslog</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 systemd-resolved[112854]: Negative trust anchors: home.arpa 10.in-addr.arpa 16.172.in-addr.arpa 17.172.in-addr.arpa 18.172.in-addr.arpa 19.172.in-addr.arpa 20.172.in-addr.arpa 21.172.in-addr.arpa 22.172.in-addr.arpa 23.172.in-addr.arpa 24.172.in-addr.arpa 25.172.in-addr.arpa 26.172.in-addr.arpa 27.172.in-addr.arpa 28.172.in-addr.arpa 29.172.in-addr.arpa 30.172.in-addr.arpa 31.172.in-addr.arpa 168.192.in-addr.arpa d.f.ip6.arpa corp home internal intranet lan l...</td>
      <td>2</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>/var/log/syslog</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 systemd-resolved[112854]: Positive Trust Anchors:</td>
      <td>2</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>filebeat</td>
      <td>/var/log/syslog</td>
      <td>Apr 29 20:01:39 ip-172-16-40-100 systemd-resolved[112854]: Using system hostname 'ip-172-16-40-100'.</td>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>




```python

```

### System boot, on/off


```python
splunk_query = f'''search index=linux "journald.process.name"=systemd (halt OR shutdown???) {query_common_args}
| stats count by host,message'''
df_system_onoff = splunk_prov.exec_query(splunk_query)
if not df_system_onoff or df_system_onoff.empty:
    print("No results")
else:
    df_system_onoff.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.17it/s]

    Warning - query did not return any results.
    No results


    
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python

```

### Error, warnings


```python
splunk_query = f'''search index=linux error {query_common_args}
| head 10'''
df_errors = splunk_prov.exec_query(splunk_query)
df_errors.head(5)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 93.31it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>_bkt</th>
      <th>_cd</th>
      <th>_indextime</th>
      <th>_raw</th>
      <th>_serial</th>
      <th>_si</th>
      <th>_sourcetype</th>
      <th>_subsecond</th>
      <th>_time</th>
      <th>agent.name</th>
      <th>host</th>
      <th>index</th>
      <th>linecount</th>
      <th>source</th>
      <th>sourcetype</th>
      <th>splunk_server</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:144246</td>
      <td>1683924149</td>
      <td>{"@timestamp":"2023-04-29T22:59:45.028Z","log":{"file":{"path":"/var/log/syslog"},"offset":148565680},"message":"Apr 29 22:59:39 ip-172-16-40-100 filebeat[109329]: {\"log.level\":\"error\",\"@timestamp\":\"2023-04-29T22:59:39.158Z\",\"log.logger\":\"publisher_pipeline_output\",\"log.origin\":{\"file.name\":\"pipeline/client_worker.go\",\"file.line\":150},\"message\":\"Failed to connect to backoff(elasticsearch(https://172.16.22.10:9200)): Get \\\"https://172.16.22.10:9200\\\": net/http: requ...</td>
      <td>0</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.028</td>
      <td>2023-04-29T22:59:45.028+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>1</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:46541</td>
      <td>1683924146</td>
      <td>{"@timestamp":"2023-04-29T22:59:45.028Z","log":{"file":{"path":"/var/log/syslog"},"offset":148565680},"message":"Apr 29 22:59:39 ip-172-16-40-100 filebeat[109329]: {\"log.level\":\"error\",\"@timestamp\":\"2023-04-29T22:59:39.158Z\",\"log.logger\":\"publisher_pipeline_output\",\"log.origin\":{\"file.name\":\"pipeline/client_worker.go\",\"file.line\":150},\"message\":\"Failed to connect to backoff(elasticsearch(https://172.16.22.10:9200)): Get \\\"https://172.16.22.10:9200\\\": net/http: requ...</td>
      <td>1</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.028</td>
      <td>2023-04-29T22:59:45.028+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>2</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:144113</td>
      <td>1683924149</td>
      <td>{"@timestamp":"2023-04-29T22:59:39.158Z","event":{"kind":"event","created":"2023-04-29T22:59:40.339Z"},"log":{"syslog":{"priority":6,"facility":{"code":3}}},"ecs":{"version":"8.0.0"},"user":{"group":{"id":"0"},"id":"0"},"process":{"args_count":13,"pid":109329,"command_line":"/usr/share/filebeat/bin/filebeat --environment systemd -c /etc/filebeat/filebeat.yml --path.home /usr/share/filebeat --path.config /etc/filebeat --path.data /var/lib/filebeat --path.logs /var/log/filebeat","args":["/usr/...</td>
      <td>2</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.158</td>
      <td>2023-04-29T22:59:39.158+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>3</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:46363</td>
      <td>1683924146</td>
      <td>{"@timestamp":"2023-04-29T22:59:39.158Z","event":{"kind":"event","created":"2023-04-29T22:59:40.339Z"},"log":{"syslog":{"priority":6,"facility":{"code":3}}},"ecs":{"version":"8.0.0"},"user":{"group":{"id":"0"},"id":"0"},"process":{"args_count":13,"pid":109329,"command_line":"/usr/share/filebeat/bin/filebeat --environment systemd -c /etc/filebeat/filebeat.yml --path.home /usr/share/filebeat --path.config /etc/filebeat --path.data /var/lib/filebeat --path.logs /var/log/filebeat","args":["/usr/...</td>
      <td>3</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.158</td>
      <td>2023-04-29T22:59:39.158+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>4</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:143940</td>
      <td>1683924149</td>
      <td>{"@timestamp":"2023-04-29T22:58:55.024Z","log":{"offset":148564147,"file":{"path":"/var/log/syslog"}},"message":"Apr 29 22:58:52 ip-172-16-40-100 filebeat[109329]: {\"log.level\":\"error\",\"@timestamp\":\"2023-04-29T22:58:52.401Z\",\"log.logger\":\"esclientleg\",\"log.origin\":{\"file.name\":\"transport/logging.go\",\"file.line\":38},\"message\":\"Error dialing dial tcp 172.16.22.10:9200: i/o timeout\",\"service.name\":\"filebeat\",\"network\":\"tcp\",\"address\":\"172.16.22.10:9200\",\"ecs...</td>
      <td>4</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.024</td>
      <td>2023-04-29T22:58:55.024+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=linux warn {query_common_args}
| head 10'''
df_warn = splunk_prov.exec_query(splunk_query)
df_warn.head(5)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 95.77it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>_bkt</th>
      <th>_cd</th>
      <th>_indextime</th>
      <th>_raw</th>
      <th>_serial</th>
      <th>_si</th>
      <th>_sourcetype</th>
      <th>_subsecond</th>
      <th>_time</th>
      <th>agent.name</th>
      <th>host</th>
      <th>index</th>
      <th>linecount</th>
      <th>source</th>
      <th>sourcetype</th>
      <th>splunk_server</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:125189</td>
      <td>1683924148</td>
      <td>{"@timestamp":"2023-04-29T22:37:33.864Z","agent":{"ephemeral_id":"fa212351-5713-49b4-8a54-651130c40eb3","id":"6cb12c8d-5f82-4045-ad01-b39039886fd5","name":"ip-172-16-40-100","type":"filebeat","version":"8.7.0"},"log":{"file":{"path":"/var/log/syslog"},"offset":148474548},"message":"Apr 29 22:37:32 ip-172-16-40-100 teleport[112836]: 2023-04-29T22:37:32Z WARN [NODE:1]    Restart watch on error: connection error: desc = \"transport: Error while dialing failed to dial: context deadline exceeded\...</td>
      <td>0</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.864</td>
      <td>2023-04-29T22:37:33.864+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>1</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:11794</td>
      <td>1683924144</td>
      <td>{"@timestamp":"2023-04-29T22:37:33.864Z","agent":{"ephemeral_id":"fa212351-5713-49b4-8a54-651130c40eb3","id":"6cb12c8d-5f82-4045-ad01-b39039886fd5","name":"ip-172-16-40-100","type":"filebeat","version":"8.7.0"},"log":{"file":{"path":"/var/log/syslog"},"offset":148474548},"message":"Apr 29 22:37:32 ip-172-16-40-100 teleport[112836]: 2023-04-29T22:37:32Z WARN [NODE:1]    Restart watch on error: connection error: desc = \"transport: Error while dialing failed to dial: context deadline exceeded\...</td>
      <td>1</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.864</td>
      <td>2023-04-29T22:37:33.864+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>2</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:125210</td>
      <td>1683924148</td>
      <td>{"@timestamp":"2023-04-29T22:37:32.751Z","systemd":{"unit":"teleport.service","invocation_id":"5417a8fb90974819b7d3e0aef8917700","slice":"system.slice","transport":"stdout","cgroup":"/system.slice/teleport.service"},"user":{"id":"0","group":{"id":"0"}},"input":{"type":"journald"},"agent":{"name":"ip-172-16-40-100","type":"filebeat","version":"8.7.0","ephemeral_id":"fa212351-5713-49b4-8a54-651130c40eb3","id":"6cb12c8d-5f82-4045-ad01-b39039886fd5"},"message":"2023-04-29T22:37:32Z WARN [NODE:1]...</td>
      <td>2</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.751</td>
      <td>2023-04-29T22:37:32.751+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>3</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:11835</td>
      <td>1683924144</td>
      <td>{"@timestamp":"2023-04-29T22:37:32.751Z","systemd":{"unit":"teleport.service","invocation_id":"5417a8fb90974819b7d3e0aef8917700","slice":"system.slice","transport":"stdout","cgroup":"/system.slice/teleport.service"},"user":{"id":"0","group":{"id":"0"}},"input":{"type":"journald"},"agent":{"name":"ip-172-16-40-100","type":"filebeat","version":"8.7.0","ephemeral_id":"fa212351-5713-49b4-8a54-651130c40eb3","id":"6cb12c8d-5f82-4045-ad01-b39039886fd5"},"message":"2023-04-29T22:37:32Z WARN [NODE:1]...</td>
      <td>3</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.751</td>
      <td>2023-04-29T22:37:32.751+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
    <tr>
      <th>4</th>
      <td>linux~18~BEE3FED0-1943-432F-A851-D74F85B46362</td>
      <td>18:124212</td>
      <td>1683924148</td>
      <td>{"@timestamp":"2023-04-29T22:36:30.853Z","log":{"offset":148470194,"file":{"path":"/var/log/syslog"}},"message":"Apr 29 22:36:30 ip-172-16-40-100 teleport[112836]: 2023-04-29T22:36:30Z WARN [PROC:1]    Sync rotation state cycle failed. Retrying in ~10s pid:112836.1 service/connect.go:709","input":{"type":"log"},"agent":{"name":"ip-172-16-40-100","type":"filebeat","version":"8.7.0","ephemeral_id":"fa212351-5713-49b4-8a54-651130c40eb3","id":"6cb12c8d-5f82-4045-ad01-b39039886fd5"},"ecs":{"versi...</td>
      <td>4</td>
      <td>[ip-172-16-22-20, linux]</td>
      <td>filebeat</td>
      <td>.853</td>
      <td>2023-04-29T22:36:30.853+00:00</td>
      <td>ip-172-16-40-100</td>
      <td>ip-172-16-40-100</td>
      <td>linux</td>
      <td>1</td>
      <td>linux</td>
      <td>filebeat</td>
      <td>ip-172-16-22-20</td>
    </tr>
  </tbody>
</table>
</div>



### Process activities


```python
splunk_query = f'''search index=sysmonforlinux {query_common_args}
| stats count by RuleName,User,Image,CommandLine,ParentCommandLine'''
df_process = splunk_prov.exec_query(splunk_query)
df_process.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 97.10it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>RuleName</th>
      <th>User</th>
      <th>Image</th>
      <th>CommandLine</th>
      <th>ParentCommandLine</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>-</td>
      <td>-</td>
      <td>/root/tools/kerbrute</td>
      <td>./kerbrute userenum -d magnumtempus.financial --dc dc.magnumtempus.financial /root/d</td>
      <td>-</td>
      <td>64</td>
    </tr>
    <tr>
      <th>1</th>
      <td>-</td>
      <td>-</td>
      <td>/snap/snapd/18933/usr/bin/snap</td>
      <td>/usr/bin/snap advise-snap --format=json --command crackmapexec</td>
      <td>/usr/bin/python3</td>
      <td>64</td>
    </tr>
    <tr>
      <th>2</th>
      <td>-</td>
      <td>-</td>
      <td>/snap/snapd/18933/usr/bin/snap</td>
      <td>/usr/bin/snap advise-snap --from-apt</td>
      <td>/bin/sh</td>
      <td>256</td>
    </tr>
    <tr>
      <th>3</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/apt-config</td>
      <td>apt-config shell ARCHIVE_KEYRING APT::Key::ArchiveKeyring</td>
      <td>/bin/sh</td>
      <td>704</td>
    </tr>
    <tr>
      <th>4</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/apt-config</td>
      <td>apt-config shell ARCHIVE_KEYRING_URI APT::Key::ArchiveKeyringURI</td>
      <td>/bin/sh</td>
      <td>704</td>
    </tr>
    <tr>
      <th>5</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/apt-config</td>
      <td>apt-config shell DpkgStatus Dir::State::status</td>
      <td>/bin/sh</td>
      <td>128</td>
    </tr>
    <tr>
      <th>6</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/apt-config</td>
      <td>apt-config shell EtcDir Dir::Etc</td>
      <td>/bin/sh</td>
      <td>128</td>
    </tr>
    <tr>
      <th>7</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/apt-config</td>
      <td>apt-config shell GPGV Apt::Key::gpgvcommand</td>
      <td>/bin/sh</td>
      <td>704</td>
    </tr>
    <tr>
      <th>8</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/apt-config</td>
      <td>apt-config shell ListDir Dir::State::Lists</td>
      <td>/bin/sh</td>
      <td>128</td>
    </tr>
    <tr>
      <th>9</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/apt-config</td>
      <td>apt-config shell MASTER_KEYRING APT::Key::MasterKeyring</td>
      <td>/bin/sh</td>
      <td>704</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=sysmonforlinux {query_common_args} (kebrute OR crackmapexec OR curl OR wget OR pip3 OR git)
| stats count by RuleName,User,Image,CommandLine,ParentCommandLine'''
df_process2 = splunk_prov.exec_query(splunk_query)
df_process2.head(20)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.84it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())





<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>RuleName</th>
      <th>User</th>
      <th>Image</th>
      <th>CommandLine</th>
      <th>ParentCommandLine</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>-</td>
      <td>-</td>
      <td>/snap/snapd/18933/usr/bin/snap</td>
      <td>/usr/bin/snap advise-snap --format=json --command crackmapexec</td>
      <td>/usr/bin/python3</td>
      <td>64</td>
    </tr>
    <tr>
      <th>1</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/curl</td>
      <td>curl http://18.220.210.56:1935/b</td>
      <td>bash</td>
      <td>128</td>
    </tr>
    <tr>
      <th>2</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/curl</td>
      <td>curl http://18.220.210.56:1935/c</td>
      <td>bash</td>
      <td>64</td>
    </tr>
    <tr>
      <th>3</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/curl</td>
      <td>curl http://18.220.210.56:1935/d</td>
      <td>bash</td>
      <td>64</td>
    </tr>
    <tr>
      <th>4</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/dpkg</td>
      <td>dpkg -l wget</td>
      <td>-</td>
      <td>64</td>
    </tr>
    <tr>
      <th>5</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/dpkg-query</td>
      <td>dpkg-query --list -- wget</td>
      <td>-</td>
      <td>64</td>
    </tr>
    <tr>
      <th>6</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/git</td>
      <td>git branch</td>
      <td>/usr/bin/python3</td>
      <td>96</td>
    </tr>
    <tr>
      <th>7</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/git</td>
      <td>git clone https://github.com/Wh04m1001/DFSCoerce</td>
      <td>-</td>
      <td>64</td>
    </tr>
    <tr>
      <th>8</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/git</td>
      <td>git clone https://github.com/lgandx/Responder</td>
      <td>-</td>
      <td>64</td>
    </tr>
    <tr>
      <th>9</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/git</td>
      <td>git rev-parse HEAD</td>
      <td>/usr/bin/python3</td>
      <td>32</td>
    </tr>
    <tr>
      <th>10</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c \nexec(compile('''\n# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py\n#\n# - It imports setuptools before invoking setup.py, to enable projects that directly\n#   import from `distutils.core` to work with newer packaging standards.\n# - It provides a clear error message when setuptools is not installed.\n# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so\n#   setuptools doesn't think the script is `-c`. Thi...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>16</td>
    </tr>
    <tr>
      <th>11</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c \nexec(compile('''\n# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py\n#\n# - It imports setuptools before invoking setup.py, to enable projects that directly\n#   import from `distutils.core` to work with newer packaging standards.\n# - It provides a clear error message when setuptools is not installed.\n# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so\n#   setuptools doesn't think the script is `-c`. Thi...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>16</td>
    </tr>
    <tr>
      <th>12</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c \nexec(compile('''\n# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py\n#\n# - It imports setuptools before invoking setup.py, to enable projects that directly\n#   import from `distutils.core` to work with newer packaging standards.\n# - It provides a clear error message when setuptools is not installed.\n# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so\n#   setuptools doesn't think the script is `-c`. Thi...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>16</td>
    </tr>
    <tr>
      <th>13</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c \nexec(compile('''\n# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py\n#\n# - It imports setuptools before invoking setup.py, to enable projects that directly\n#   import from `distutils.core` to work with newer packaging standards.\n# - It provides a clear error message when setuptools is not installed.\n# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so\n#   setuptools doesn't think the script is `-c`. Thi...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>16</td>
    </tr>
    <tr>
      <th>14</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c \nexec(compile('''\n# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py\n#\n# - It imports setuptools before invoking setup.py, to enable projects that directly\n#   import from `distutils.core` to work with newer packaging standards.\n# - It provides a clear error message when setuptools is not installed.\n# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so\n#   setuptools doesn't think the script is `-c`. Thi...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>16</td>
    </tr>
    <tr>
      <th>15</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c \nexec(compile('''\n# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py\n#\n# - It imports setuptools before invoking setup.py, to enable projects that directly\n#   import from `distutils.core` to work with newer packaging standards.\n# - It provides a clear error message when setuptools is not installed.\n# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so\n#   setuptools doesn't think the script is `-c`. Thi...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>16</td>
    </tr>
    <tr>
      <th>16</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c  exec(compile(''' # This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py # # - It imports setuptools before invoking setup.py, to enable projects that directly #   import from `distutils.core` to work with newer packaging standards. # - It provides a clear error message when setuptools is not installed. # - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so #   setuptools doesn't think the script is `-c`. This avoids...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>96</td>
    </tr>
    <tr>
      <th>17</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c #012exec(compile('''#012# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py#012##012# - It imports setuptools before invoking setup.py, to enable projects that directly#012#   import from `distutils.core` to work with newer packaging standards.#012# - It provides a clear error message when setuptools is not installed.#012# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so#012#   setuptools doesn't think the scr...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>112</td>
    </tr>
    <tr>
      <th>18</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c #012exec(compile('''#012# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py#012##012# - It imports setuptools before invoking setup.py, to enable projects that directly#012#   import from `distutils.core` to work with newer packaging standards.#012# - It provides a clear error message when setuptools is not installed.#012# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so#012#   setuptools doesn't think the scr...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install install crackmapexec</td>
      <td>48</td>
    </tr>
    <tr>
      <th>19</th>
      <td>-</td>
      <td>-</td>
      <td>/usr/bin/python3.10</td>
      <td>/usr/bin/python3 -c #012exec(compile('''#012# This is &amp;lt;pip-setuptools-caller&amp;gt; -- a caller that pip uses to run setup.py#012##012# - It imports setuptools before invoking setup.py, to enable projects that directly#012#   import from `distutils.core` to work with newer packaging standards.#012# - It provides a clear error message when setuptools is not installed.#012# - It sets `sys.argv[0]` to the underlying `setup.py`, when invoking `setup.py` so#012#   setuptools doesn't think the scr...</td>
      <td>/usr/bin/python3 /usr/bin/pip3 install -r ../requirements.txt</td>
      <td>16</td>
    </tr>
  </tbody>
</table>
</div>




```python

```


```python
splunk_query = f'''search index=sysmonforlinux {query_common_args} (kebrute OR crackmapexec OR curl OR wget OR pip3 OR git OR 11317)
| stats count by host,RuleName,UtcTime,User,Image,ProcessId,CommandLine,ParentProcessId,ParentCommandLine'''
df_process_tree = splunk_prov.exec_query(splunk_query)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.03it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python
df_process_tree.head(5)
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>RuleName</th>
      <th>UtcTime</th>
      <th>User</th>
      <th>Image</th>
      <th>ProcessId</th>
      <th>CommandLine</th>
      <th>ParentProcessId</th>
      <th>ParentCommandLine</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>ip-172-16-40-100</td>
      <td>-</td>
      <td>2023-04-29 17:53:35.074</td>
      <td>-</td>
      <td>/usr/bin/dpkg</td>
      <td>110493</td>
      <td>dpkg -l wget</td>
      <td>110492</td>
      <td>-</td>
      <td>512</td>
    </tr>
    <tr>
      <th>1</th>
      <td>ip-172-16-40-100</td>
      <td>-</td>
      <td>2023-04-29 17:53:35.074</td>
      <td>-</td>
      <td>/usr/bin/dpkg-query</td>
      <td>110493</td>
      <td>dpkg-query --list -- wget</td>
      <td>110492</td>
      <td>-</td>
      <td>512</td>
    </tr>
    <tr>
      <th>2</th>
      <td>ip-172-16-40-100</td>
      <td>-</td>
      <td>2023-04-29 17:53:35.542</td>
      <td>-</td>
      <td>/usr/bin/wget</td>
      <td>110511</td>
      <td>wget --timeout 60 -U wget/1.21.2-2ubuntu1 Ubuntu/22.04.1/LTS GNU/Linux/5.15.0-1028-aws/x86_64 Intel(R)/Xeon(R)/Platinum/8259CL/CPU/@/2.50GHz cloud_id/aws -O- --content-on-error https://motd.ubuntu.com</td>
      <td>110488</td>
      <td>/bin/sh</td>
      <td>256</td>
    </tr>
    <tr>
      <th>3</th>
      <td>ip-172-16-40-100</td>
      <td>-</td>
      <td>2023-04-29 19:59:29.656</td>
      <td>-</td>
      <td>/usr/bin/curl</td>
      <td>111340</td>
      <td>curl http://18.220.210.56:1935/b</td>
      <td>111317</td>
      <td>bash</td>
      <td>512</td>
    </tr>
    <tr>
      <th>4</th>
      <td>ip-172-16-40-100</td>
      <td>-</td>
      <td>2023-04-29 19:59:58.504</td>
      <td>-</td>
      <td>/usr/bin/curl</td>
      <td>111343</td>
      <td>curl http://18.220.210.56:1935/b</td>
      <td>111317</td>
      <td>bash</td>
      <td>512</td>
    </tr>
  </tbody>
</table>
</div>




```python
df_process_tree[df_process_tree['ProcessId'] == 11317]
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>host</th>
      <th>RuleName</th>
      <th>UtcTime</th>
      <th>User</th>
      <th>Image</th>
      <th>ProcessId</th>
      <th>CommandLine</th>
      <th>ParentProcessId</th>
      <th>ParentCommandLine</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>
</div>




```python
# Process tree
from msticpy.transform.proc_tree_builder import LX_EVENT_SCH
from copy import copy
cust_lx_schema = copy(LX_EVENT_SCH)

cust_lx_schema.time_stamp = "UtcTime"
cust_lx_schema.host_name_column = "host"
cust_lx_schema.cmd_line = "CommandLine"
cust_lx_schema.process_name = "Image"
cust_lx_schema.process_id = "ProcessId"
cust_lx_schema.parent_id = "ParentProcessId"
cust_lx_schema.user_name = "User"
cust_lx_schema.event_id_column = None
cust_lx_schema.event_id_identifier = None

# now supply the schema as the schema parameter
#process_tree.build_process_tree(df_process_tree, schema=cust_lx_schema)
df_process_tree.mp_plot.process_tree(schema=cust_lx_schema)
```

    /usr/local/lib/python3.10/dist-packages/bokeh/io/notebook.py:487: DeprecationWarning: The `source` parameter emit a  deprecation warning since IPython 8.0, it had no effects for a long time and will  be removed in future versions.
      publish_display_data(data, metadata, source, transient=transient, **kwargs)



<div class="bk-root">
        <a href="https://bokeh.org" target="_blank" class="bk-logo bk-logo-small bk-logo-notebook"></a>
        <span id="1002">Loading BokehJS ...</span>
    </div>





    /usr/local/lib/python3.10/dist-packages/bokeh/io/notebook.py:487: DeprecationWarning: The `source` parameter emit a  deprecation warning since IPython 8.0, it had no effects for a long time and will  be removed in future versions.
      publish_display_data(data, metadata, source, transient=transient, **kwargs)




<div class="bk-root" id="36f9ce74-568e-4405-9331-908f9940054c" data-root-id="1175"></div>








    (Figure(id='1036', ...), Row(id='1175', ...))




```python

```


```python
splunk_query = f'''search index=osquery pack_osquery-custom-pack_processes {query_common_args}
| spath input=message
| where name="pack_osquery-custom-pack_outbound_connections"
| stats count by name,action,columns.pid,columns.cmdline,columns.ppid,columns.pcmdline'''
df_process9 = splunk_prov.exec_query(splunk_query)
if not df_process9 or df_process9.empty:
    print("No results")
else:
    df_process9.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 97.00it/s]

    Warning - query did not return any results.
    No results


    
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python

```

### Network activities


```python
splunk_query = f'''search index=osquery pack_osquery-custom-pack_dns_resolvers {query_common_args}
| spath input=message
| where name="pack_osquery-custom-pack_dns_resolvers"
| stats count by name,action,columns.address,columns.type'''
df_dns = splunk_prov.exec_query(splunk_query)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 94.61it/s]
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python
 df_dns.head(10)
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>name</th>
      <th>action</th>
      <th>columns.address</th>
      <th>columns.type</th>
      <th>count</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>pack_osquery-custom-pack_dns_resolvers</td>
      <td>removed</td>
      <td>127.0.0.53</td>
      <td>nameserver</td>
      <td>1</td>
    </tr>
    <tr>
      <th>1</th>
      <td>pack_osquery-custom-pack_dns_resolvers</td>
      <td>removed</td>
      <td>172.16.50.100</td>
      <td>nameserver</td>
      <td>1</td>
    </tr>
  </tbody>
</table>
</div>




```python
splunk_query = f'''search index=osquery pack_osquery-custom-pack_outbound_connections {query_common_args}
| spath input=message
| where name="pack_osquery-custom-pack_outbound_connections"
| stats count by name,action,columns.username,columns.name,columns.path,columns.cmdline,columns.remote_address'''
df_outbound = splunk_prov.exec_query(splunk_query)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 94.88it/s]

    Warning - query did not return any results.


    
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python
if not df_outbound or df_outbound.empty:
    print("No results")
else:
    df_outbound.head(10)
```

    No results



```python

```

### File Integrity Monitoring


```python
splunk_query = f'''search index=osquery fim {query_common_args}
| spath input=message
| where name="fim"
| stats count by name,columns.target_path,columns.action'''
df_fim = splunk_prov.exec_query(splunk_query)
if not df_fim or df_fim.empty:
    print("No results")
else:
    df_fim.head(10)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 96.43it/s]

    Warning - query did not return any results.
    No results


    
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())


### Misc


```python
splunk_prov.list_queries()
```




    ['Alerts.list_alerts',
     'Alerts.list_alerts_for_dest_ip',
     'Alerts.list_alerts_for_src_ip',
     'Alerts.list_alerts_for_user',
     'Alerts.list_all_alerts',
     'Authentication.list_logon_failures',
     'Authentication.list_logons_for_account',
     'Authentication.list_logons_for_host',
     'Authentication.list_logons_for_source_ip',
     'SplunkGeneral.get_events_parameterized',
     'SplunkGeneral.list_all_datatypes',
     'SplunkGeneral.list_all_savedsearches',
     'audittrail.list_all_audittrail']




```python
splunk_query = f'''search index=osquery pack_osquery-custom-pack_python_packages {query_common_args}
| search name="pack_osquery-custom-pack_python_packages"
| stats count by name,action,columns.name,columns.summary,columns.version'''
df_python = splunk_prov.exec_query(splunk_query)
```

    Waiting Splunk job to complete: 100%|██████████| 100.0/100 [00:01<00:00, 95.62it/s]

    Warning - query did not return any results.


    
    /usr/local/lib/python3.10/dist-packages/msticpy/data/drivers/splunk_driver.py:234: DeprecationWarning: ResultsReader is a deprecated function. Use the JSONResultsReader function instead in conjuction with the 'output_mode' query param set to 'json'
      reader = sp_results.ResultsReader(query_job.results())



```python
if not df_python or df_python.empty:
    print("No results")
else:
    df_python.head(10)
```

    No results



```python

```


```python

```
