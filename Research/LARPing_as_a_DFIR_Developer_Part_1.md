# LARPing as a DFIR Developer Part 1
## Outline
I was looking into dumping the swap file (and other system locked files) and wanted a way that would be hard to signature and isnt blocked by AV / EDR. I found out you can just dump the MFT from the physical drive and parse out the files you need. (Similar to parsing out lsass secrets from ram). This doesnt seem to be used by the 2 DFIR tools reversed but I'm sure it is a known technique.

## Intro
With Windows 10 fast approaching EoL I thought I should finally look into whatever this Windows 11 thing is and if there are any additional security features. A bit late I know but better late then never. While looking at the enabled by default settings I found out that both bitlocker and Protected Process Light (PPL) for lsass are enabled, which i found interesting as this should kill most dumping primitives as you can no longer get a valid handle to the process.

This is nothing new as PPL has been around since Windows 8.1 (A long time ago) and there has been a heap of research around exploits and bypasses but thinking about PPL its basically an ACL on the process handles. So instead of trying to access the memory via its mapped Virtual memory in the process, why not just dump all of the physical memory and parse it out that way. This works as all currently used virtual memory is mapped directly to RAM and can be translated by the kernel. 

Again this is nothing new and is known trade craft (it even has its own MITRE ATT&CK code for all you purple team people out there. Most tools will use a driver and simply dump out all the ram to a file on disk. Then you can use volatility3 to extract the LSA secrets.
```
./vol.py -f ramdump.mem windows.lsadump.Lsadump
```
(You could also extract lsass.exe and then dump that with mimikatz on a remote host.)

This is pretty effective and opsec safe as this is a normal thing that DFIR people will do when they need to capture the contents of a machine. You can also use this a primitive to dump files, such as the SAM SYSTEM and SECURITY hives, but what if a page is swapped out to disk?

## Windows Memory Management
Sometimes when I've gone to extract secrets from memory the tool has complained that the file cant be found or that it needs a swap file. First what even is a swap file?

A swap file is basically a file on disk that is the overflow of you ram. So if there is a unit of memory (a page - normally 4kb in size) that has not been accessed in a while, the kernel will swap the page out to the swap file allowing for more free memory to be accessed and allocated. The way this is implemented is pretty cool too.
Let's say you have a program called notmalware.exe that doesnt run malware and instead allocates 12mb of random binary data and sleeps for 40minutes. If this was to run at system boot by the time you are going to use the 12mb of data the machine has probably launched a browser with 100 tabs, slack and teams. 
This will result in a chance that the pages have been swapped to disk. When the process will access the virtual memory the kernel will convert the virtual memory address to a physical memory location and check the first bit of the pointer. If this is set then it is in the swap file and instead will cast the pointer to an offset and swap the page back into ram. So lets just grab the swap file and let vol.py do all the work.

## System locked Files
So like every good developer I asked ChatGPT:
Prompt:
```
Using the windows api in c and you open the pagefile.sys file?
```

Reply:
```
Opening `pagefile.sys` on Windows is highly restricted due to its role in virtual memory management. The file is locked by the system, so even with administrative privileges, you generally cannot open it for reading or writing while Windows is running.
```
Code:
```c
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFile(
        "C:\\pagefile.sys",
        GENERIC_READ,            // Attempt to read
        FILE_SHARE_READ,         // Allow sharing
        NULL,                    // Security attributes
        OPEN_EXISTING,           // Open only if it exists
        FILE_ATTRIBUTE_NORMAL,   // Normal file attributes
        NULL                     // No template file
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open pagefile.sys. Error: %lu\n", GetLastError());
    } else {
        printf("Successfully opened pagefile.sys (this is highly unlikely!).\n");
        CloseHandle(hFile);
    }

    return 0;
}

```

Well that sounds annoying but going to try anyways.
```
.\chatgpt_code.exe
Failed to open pagefile.sys. Error: 2
```

My first thought was lets just disable the swap file, While you can do this and it would fix all your issues you need a reboot and what if the computer reboots once every couple of years instead of on demand. My second thought was there has to be a driver for this. Then I thought if DFIR tools can do it why cant I? So i started to look into reversing and understanding forensics tools.

There is a git repo that lets you pick which tool to use:
https://github.com/LETHAL-FORENSICS/Collect-MemoryDump/blob/main/Collect-MemoryDump.ps1
It also has a flag to dump the pagefile. Quickly analysing the Magnet RESPONSE binary shows that it does not call a driver and instead seems to open the physical drive. 

This concept makes sense as its basically the same as the PPL bypass described above but for files. The system has a lock on a sector (the file equivalent of a page) and is filtering the access control. So instead of trying to access the sector via the implementation, NTFS in this case (For PPL it was Virtual Memory) lets grab the physical drive and carve out the file. Unlike RAM we cant write the entire disk to disk as we will run out of space, I also dont really want to have to wait to exfiltrate the entire disk. Instead we can just grab what we need and write that to disk (Just for the POC, ideally you would want to encrypt this and use it or send it via a c2 channel).

## NTFS
How does NTFS work? I have no idea, but i do know of this magical file called the Master File Table (MFT) that should contain all the files in some sort of table that we can loop over till we find the one we want.

Prompt:
```
Can you open the MFT?
```

Code:
```c
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hMFT = CreateFile(
        "\\\\.\\C:\\$MFT",       // Path to the MFT
        GENERIC_READ,            // Read access
        FILE_SHARE_READ,         // Allow sharing
        NULL,                    // Default security
        OPEN_EXISTING,           // Open only if exists
        FILE_ATTRIBUTE_NORMAL,   // Normal attributes
        NULL                     // No template
    );

    if (hMFT == INVALID_HANDLE_VALUE) {
        printf("Failed to open $MFT. Error: %lu\n", GetLastError());
    } else {
        printf("Successfully opened $MFT!\n");
        CloseHandle(hMFT);
    }

    return 0;
}

```

Running the code
```
.\chatgpt_code.exe
Failed to open $MFT. Error: 2
```

I guess we also have to parse out the MFT too. :(

I found this article that seems to be doing just that, instead of trying to badly explain it I suggest you just read it yourself: https://handmade.network/forums/articles/t/7002-tutorial_parsing_the_mft

The best thing is that they provided a full code sample at the end :) Compiling and running the code shows that it indeed does work and is able to get the FILE attribute of the pageflie.sys file from the MFT. (much better then what chatgpt has done so far.)

With this code we can modify it to check if the `$FILE` name attribute is the one we are looking for then get the file data. As the swapfile will be bigger then 4kb it will be a Nonresident file so we can grab the dataruns.

```cpp
	NonResidentAttributeHeader* file_dataAttribute = nullptr;

	while ((uint8_t*)attribute - (uint8_t*)fileRecord < MFT_FILE_SIZE) {
		if (attribute->attributeType == 0x30) {
			fileNameAttribute = (FileNameAttributeHeader*)attribute;
		}

		if (attribute->attributeType == 0x80) {
			file_dataAttribute = (NonResidentAttributeHeader*)attribute;
		}

		else if (attribute->attributeType == 0xFFFFFFFF) {
			break;
		}

		attribute = (AttributeHeader*)((uint8_t*)attribute + attribute->length);
	}
    char* name = DuplicateName(fileNameAttribute->fileName, fileNameAttribute->fileNameLength);
	if (strcmp(name, "pagefile.sys") == 0){
        if (file_dataAttribute->nonResident == 0) {
            printf("[Error] File is resident, no Data Runs available!\n");
            return 0;
        }
        else {
            printf("File is a non resident file\n");
        }
		RunHeader* file_dataRun = (RunHeader*)((uint8_t*)file_dataAttribute + file_dataAttribute->dataRunsOffset);
        printf("file_dataRun->lengthFiledBytes: %llu\n", file_dataRun->lengthFieldBytes);
        printf("file_dataRun->offsetfieldbytes: %llu\n", file_dataRun->offsetFieldBytes);

        uint64_t file_clusterNumber = 0;
        LPVOID outputbuffer = NULL;

        while (((uint8_t*)file_dataRun - (uint8_t*)file_dataAttribute) < file_dataAttribute->length && file_dataRun->lengthFieldBytes) {
            uint64_t length = 0,
                offset = 0;
            for (int i = 0; i < file_dataRun->lengthFieldBytes; i++) {
                length |= (uint64_t)(((uint8_t*)file_dataRun)[1 + i]) << (i * 8);
            }
            for (int i = 0; i < file_dataRun->offsetFieldBytes; i++) {
                offset |= (uint64_t)(((uint8_t*)file_dataRun)[1 + file_dataRun->lengthFieldBytes + i]) << (i * 8);
            }
            if (offset & ((uint64_t)1 << (file_dataRun->offsetFieldBytes * 8 - 1))) {
                for (int i = file_dataRun->offsetFieldBytes; i < 8; i++) {
                    offset |= (uint64_t)0xFF << (i * 8);
                }
            }

            file_clusterNumber += offset;
            file_dataRun = (RunHeader*)((uint8_t*)file_dataRun + 1 + file_dataRun->lengthFieldBytes + file_dataRun->offsetFieldBytes);

            printf("%llu sectors starting at cluster id: %llu\n", length, file_clusterNumber);
```

Running the modified code will show the sectors that the file is mapped too.
```powershell
.\phys_sector_dump.exe
File is a non resident file
file_dataRun->lengthFiledBytes: 3
file_dataRun->offsetfieldbytes: 4
622592 sectors starting at cluster id: 23403438
```

All that is left to do is write the file to disk. (full code on github: LINK).
There is a risk of the swap file being updated after you have read the sectors but I couldnt find a way to get around this as it seems to be a race condition by design. All the forensics tools I could find that do this just say to dump the swap file right after a memory dump.

My only advice would be to allocate all the space you need on the heap with VirtualAlloc before you dump ram and make sure the ram dumping tool isnt not over allocating memory when writing to a disk.

## Closing Thoughts
My current thoughts are why not just do everything dynamically in memory, to decrypt lsa secrets you need to access the registry hives anyways, so why just parse out the lsa secrets in memory and resolve the pointers to the swap file as you need them. This would result in just needing to exfil the decrypted secrets which is a lot easier then 16Gb of memory. 
