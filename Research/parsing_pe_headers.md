# Parsing PE Headers

## Outline
*This was going to be one post but it got kinda long so here is part one.*
I'm getting really annoyed of having to look up offsets and recompile driver exploits for different OS's and thought surely there is a way that this can be done automagically at execution time. My first thought was "well if windbg knows the size of a structure then why cant i?" (Parsing the actual PDB will be in part 2)

## Windbg and PDB files
How i normally go about finding offsets is by creating a VM with the same major version of the OS i am targeting (for all the code snippets it will be Windows 11 24H2.), hooking up a debugger and dumping the structure:
```c
0: kd> dt nt!_Token TokenFlags Capabilities
   +0x0c8 TokenFlags   : Uint4B
   +0x318 Capabilities : Ptr64 _SID_AND_ATTRIBUTES
```

Then hard coding it in for the exploit:
```c
#define TokenFlags 0x0c8
```

While this works it absolutely sucks to do every single time. So instead I started to look into how windbg knows which Program DataBase (PDB) to pull from microsoft and use within windbg. Quickly dumping out the headers showed that the pdb string is represented as a GUID within the debug directories of the files (This wont be the case for all PEs as some dont have public symbols).
```json
dumpbin /headers ntoskrnl.exe
...
  Debug Directories

        Time Type        Size      RVA  Pointer
    -------- ------- -------- -------- --------
    BCA5A8DD cv            25 000410C0    408C0    Format: RSDS, {B6121DA1-5DDC-F625-C8C7-273C0D85EB10}, 1, ntkrnlmp.pdb
    BCA5A8DD coffgrp     1574 000410E8    408E8    50475500 (PGU)
    BCA5A8DD repro         24 000426DC    41EDC    A1 1D 12 B6 DC 5D 25 F6 C8 C7 27 3C 0D 85 EB 10 C8 8B E5 B6 CF 5D FD EC EE 8E 7C 5F DD A8 A5 BC
```

I dont know what the other 2 are so im going to forget about them and just focus on the cv one. 

You can also do this in windbg:
```c
0: kd> !lmi nt
Loaded Module Info: [nt] 
         Module: ntkrnlmp
   Base Address: fffff801d3260000
     Image Name: ntkrnlmp.exe
   Machine Type: 34404 (X64)
     Time Stamp: 93dad125 (This``` is a reproducible build file hash, not a true timestamp)
           Size: 1450000
       CheckSum: c64ecc
Characteristics: 22  
Debug Data Dirs: Type  Size     VA  Pointer
             CODEVIEW    25, 589f0,   589f0 RSDS - GUID: {91F95759-B8A1-C35A-0A97-73FCA2A8A67E}
               Age: 1, Pdb: ntkrnlmp.pdb
                 POGO   920, 58a18,   58a18 [Data not mapped]
                REPRO    24, 593b8,   593b8 Reproducible build
           DLLCHAR_EX     4, 593dc,   593dc Extended DLL characteristics: 00000081
                                                 CET compatible
                                                 (Unknown)
     Image Type: MEMORY   - Image read successfully from loaded memory.
    Symbol Type: PDB      - Symbols loaded successfully from image header.
                 C:\ProgramData\Dbg\sym\ntkrnlmp.pdb\91F95759B8A1C35A0A9773FCA2A8A67E1\ntkrnlmp.pdb
```
 Once you have the GUID and the pdb filename you can download the file from microsofts symbols store:
```
https://msdl.microsoft.com/download/symbols/{filename}/{guid}{age}/{filename}
```

## PE Headers
While this is cool ideally i want to be able to do this with just a file handle so i can later turn it into a Beacon Object File (BOF). Which finally lead me to the PE headers. After reading https://learn.microsoft.com/en-us/windows/win32/debug/pe-format a few times and reading a few other posts we need to read the DOS header which will have a pointer to the NT headers. The NT headers will have section headers and then we can finally read out the debug directory entries.

We can check if the DOS header and NT header are valid before hand too.
```c
IMAGE_DOS_HEADER dos_header = { 0 };
fread(&dos_header, 1, sizeof(dos_header), fp);
if (dos_header.e_magic != 0x5a4d){ // MZ printf("Not a valid PE file\n"); fclose(fp);
		return 1;
}

fseek(fp, dos_header.e_lfanew, SEEK_SET);

IMAGE_NT_HEADERS64 nt_header = { 0 };
fread(&nt_header, 1, sizeof(nt_header), fp);
if (nt_header.Signature != 0x00004550){ // PE\0\0
		printf("Bad PE signature\n");
		fclose(fp);
		return 1;
}
```

Next is to read the section headers and get the debug directory entries.

```c
long rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER *sections, int nsects) {
    for (int i = 0; i < nsects; i++) {
        DWORD va = sections[i].VirtualAddress;
        DWORD sz = sections[i].SizeOfRawData;
        if (rva >= va && rva < va + sz) {
            return (rva - va) + sections[i].PointerToRawData;
        }
    }
    return -1; // not found
}

int nt_sections = nt_header.FileHeader.NumberOfSections;

IMAGE_SECTION_HEADER *sections = calloc(nt_sections, sizeof(IMAGE_SECTION_HEADER));
fread(sections, sizeof(IMAGE_SECTION_HEADER), nt_sections, fp);

IMAGE_DATA_DIRECTORY debug_directory_info = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

if (debug_directory_info.VirtualAddress == 0 || debug_directory_info.Size == 0) {
		printf("No debug directories found.\n");
		free(sections);
		fclose(fp);
		return 0;
}

long debug_directory_offset = rva_to_offset(debug_directory_info.VirtualAddress, sections, nt_sections);
int count = debug_directory_info.Size / sizeof(IMAGE_DEBUG_DIRECTORY);

printf("Debug Directory: RVA=0x%x Size=%u -> offset=0x%lx (%d entries)\n", debug_directory_info.VirtualAddress, debug_directory_info.Size, debug_directory_offset, count);

fseek(fp, debug_directory_offset, SEEK_SET);
for (int i = 0; i < count; i++) {
	IMAGE_DEBUG_DIRECTORY dir = {0};
	fread(&dir, sizeof(dir), 1, fp);

	printf("Entry %d:\n", i);
	printf("  TimeDateStamp     : 0x%08x\n", dir.TimeDateStamp);
	printf("  MajorVersion      : %u\n", dir.MajorVersion);
	printf("  MinorVersion      : %u\n", dir.MinorVersion);
	printf("  Type              : %u\n", dir.Type);
	printf("  SizeOfData        : %u\n", dir.SizeOfData);
	printf("  AddressOfRawData  : 0x%08x\n", dir.AddressOfRawData);
	printf("  PointerToRawData  : 0x%08x\n", dir.PointerToRawData);
}
```

Running the above against ntoskrnl shows the exact same thing as dumpbin.
```python
./get_pdb ntoskrnl.exe 
Debug Directory: RVA=0x42110 Size=112 -> offset=0x42110 (4 entries)
Entry 0:
  TimeDateStamp     : 0x93dad125
  MajorVersion      : 0
  MinorVersion      : 0
  Type              : 2
  SizeOfData        : 37
  AddressOfRawData  : 0x000589f0
  PointerToRawData  : 0x000589f0
Entry 1:
  TimeDateStamp     : 0x93dad125
  MajorVersion      : 0
  MinorVersion      : 0
  Type              : 13
  SizeOfData        : 2336
  AddressOfRawData  : 0x00058a18
  PointerToRawData  : 0x00058a18
Entry 2:
  TimeDateStamp     : 0x93dad125
  MajorVersion      : 0
  MinorVersion      : 0
  Type              : 16
  SizeOfData        : 36
  AddressOfRawData  : 0x000593b8
  PointerToRawData  : 0x000593b8
Entry 3:
  TimeDateStamp     : 0x93dad125
  MajorVersion      : 0
  MinorVersion      : 0
  Type              : 20
  SizeOfData        : 4
  AddressOfRawData  : 0x000593dc
  PointerToRawData  : 0x000593dc
```

Finally we can check if the debug type (https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type) and then dump out the buffer which should be the pdb and follow this structure. (https://www.debuginfo.com/articles/debuginfomatch.html) 
```c
struct CV_INFO_PDB70
{
  DWORD  CvSignature;
  GUID Signature;
  DWORD Age;
  BYTE PdbFileName[];
};
```

We can also check if the signature matches "RSDS".

```c
if (dir.Type == 2){
...
	void *buf = malloc(dir.SizeOfData);

	//CV_INFO_PDB70 cv_info_obj = { 0 };
	fseek(fp, dir.PointerToRawData, SEEK_SET);
	fread(buf, 1, dir.SizeOfData, fp);

	CV_INFO_PDB70 *cv_info_obj = (CV_INFO_PDB70 *)buf;
	//fread(&cv_info_obj, sizeof(cv_info_obj), 1, fp);

	if ( cv_info_obj->CvSignature != 0x53445352){
			printf("Not a valid PDB7 signature\n");
			return 1;
	}
	printf("Valid CodeView (RSDS) record found\n");
	printf("  GUID: %08x-%04x-%04x-%02x-%02x\n",
			   cv_info_obj->Signature.Data1,
			   cv_info_obj->Signature.Data2,
			   cv_info_obj->Signature.Data3);
	for (int i = 0; i < 2; i++) printf("%02x", cv_info_obj->Signature.Data4[i]);
	printf("-");
	for (int i = 2; i < 8; i++) printf("%02x", cv_info_obj->Signature.Data4[i]);
	printf("\n");
	printf("  Age: %u\n", cv_info_obj->Age);
	printf("  PDB: %s\n", cv_info_obj->PdbFileName);
```

which results in:
```python
Debug Directory: RVA=0x42110 Size=112 -> offset=0x42110 (4 entries)
Entry 0:
  TimeDateStamp     : 0x93dad125
  MajorVersion      : 0
  MinorVersion      : 0
  Type              : 2
  SizeOfData        : 37
  AddressOfRawData  : 0x000589f0
  PointerToRawData  : 0x000589f0
Valid CodeView (RSDS) record found
  GUID: 91f95759-b8a1-c35a-0a97-73fca2a8a67e
  Age: 1
  PDB: ntkrnlmp.pdb
```

: D

Final step is to download the file and check the checksum against the one that windbg uses.
```python
$ wget https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/91f95759b8a1c35a0a9773fca2a8a67e1/ntkrnlmp.pdb
$ sha256sum ntkrnlmp.pdb 
72c26e96cf9a147b8f460faf7803f1787b5a81ff6634aec1252556c585aca161  ntkrnlmp.pdb
---
PS > Get-FileHash C:\ProgramData\Dbg\sym\ntkrnlmp.pdb\91F95759B8A1C35A0A9773FCA2A8A67E1\ntkrnlmp.pdb

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          72C26E96CF9A147B8F460FAF7803F1787B5A81FF6634AEC1252556C585ACA161       C:\ProgramData\Dbg\sym\ntkrnl...
```

TaDa!

Full code: https://github.com/ElJayRight/code_from_blog_posts/tree/main/parse_pe_headers

## Closing Thoughts
While this will work for most files, it wont be able to handle a PE32 or if the pdb is the old PDB2.0 format. I'll fix these issues if they ever come up while using the tool. With the end goal of using this as a BOF i didnt really see any need to update the code to have the ability to download the pdb file. (tbh i havent fleshed out the full project yet lol).

Next post I'll look at what a pdb file is and how do i parse one on linux.

## References
https://stackoverflow.com/questions/3899573/what-is-a-pdb-file

https://www.debuginfo.com/articles/debuginfomatch.html

https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type

https://stackoverflow.com/questions/3092609/how-to-get-field-names-and-offsets-of-a-struct-using-dbghlp-and-pdb
