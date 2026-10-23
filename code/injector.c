#include <windows.h>
#include <ntdll_imit.h>
#include <tetris.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// injectDLL() can be used by everybody for any project. This is abstraction and specifically useful when
// you want to inject dll to remote process but you cannot use high level apis like LoadLibary().
// inject DlL manually maps dll to remote process address space + resolves its IAT (injects all dependency dlls and resolves their IATS as well)

char** extractMapping4VirtualDll(HANDLE,PROCESS_BASIC_INFORMATION,char*,unsigned int*);
bool compare(char*,char*);

extern __uint64_t* injectDLL(
    HANDLE proc,
    PROCESS_BASIC_INFORMATION pinfo,
    char* dll,
    char*** loadedDlls,
    size_t* count,
    int* exportedDirBaseCount
)
    {

    printf("injecDll() started execution for %s!\n",dll);

    char* searchDirectory="C:\\Windows\\System32\\";
    char* dll_file=calloc(strlen(searchDirectory)+strlen(dll)+1,sizeof(char));
    strcpy(dll_file,searchDirectory);
    strcat(dll_file,dll);
    

    HANDLE hDll=CreateFileA(
        dll_file,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if(hDll==INVALID_HANDLE_VALUE)
    {   // vergiliusproject.com 
      printf("file  does not exist on disk so calling extractMapping4VirtualDll()\n");
       int mappedDLLsCount=0;
      // mapped dlls list (could be only one or more)
      char** realDllsList=extractMapping4VirtualDll(proc,pinfo,dll,&mappedDLLsCount);
      // exported directory bases of inejcted dlls
      if(!mappedDLLsCount){
        printf("could not find virtual --- real dll mapping on system!\n");
        exit(1);
      }
      
      for(int i=0;i<mappedDLLsCount;i++)
        printf("mapped dll list for dll: %s is %s\n",dll,realDllsList[i]);
      
      __uint64_t *exportDirBases=(__uint64_t*)malloc(sizeof(__uint64_t)*mappedDLLsCount);
      for(unsigned int ifnece=0;ifnece<mappedDLLsCount;ifnece++){
        __uint64_t *exportDirBase=injectDLL(
            proc,
            pinfo,
            realDllsList[ifnece],
            loadedDlls,
            count,
            exportedDirBaseCount
        );
        exportDirBases[ifnece]=(__uint64_t)(*exportDirBase);
      }      

      return exportDirBases;

    }
    else 
    {
    DWORD onDiskSz=GetFileSize(hDll,NULL);
    char* dll_buff=(char*)malloc(onDiskSz);
    if(!ReadFile(
        hDll,
        dll_buff,
        onDiskSz,
        NULL,
        NULL
    )){
        printf("[-] 337 failed to read dll file\n");
        exit(1);
    }

    MappingMetadata dll_mm=PEParser(dll_buff);
    IMAGE_SECTION_HEADER* dll_relloc=NULL;
    BYTE* dllBase=(BYTE*)mapRoutineX(proc,dll_mm,&dll_relloc);
    if(dllBase)
        printf("DLL: %s has been mapped successfully!/n",dll);

    // if(dll_relloc)
    //     rellocate(proc,dllBase,(void*)dll_mm.heapBase,(void*)dll_mm.preferedBase,dll_relloc);

    printf("updated loaded dll list:\n");
    // till this point works.

    syncLoadedDlls(dll,loadedDlls,count);
    dumpLoadedDlls(*loadedDlls,count);

    printf("is about to resolve IAT!\n");
    resolveIAT(proc,pinfo,dllBase,loadedDlls,count);
    
    __uint64_t *exportDirBases=(__uint64_t*)malloc(sizeof(__uint64_t));
    

    *exportDirBases=(__uint64_t)((__uint64_t)dllBase+(dll_mm.dataDirectoryList+IMAGE_DIRECTORY_ENTRY_EXPORT));
    ++(*exportedDirBaseCount);
    return exportDirBases;
    
}

}



// by virtual dll i mean api set dlls which actuaally get to be mapped to real dll existing on disk 
char** extractMapping4VirtualDll(HANDLE proc,PROCESS_BASIC_INFORMATION pinfo,char* dll,unsigned int* mappedDllsCount){
        
        char** mappedDLls=(char**)malloc(sizeof(char*));
        *mappedDLls=NULL;
        size_t targetDllSz=strlen(dll);
        // format will be some-dll-name-x-y-z
        char targetDll[targetDllSz+1];
        targetDll[targetDllSz]='\0';
        strcpy(targetDll,dll);
        *strrchr(targetDll,'.')='\0';

        __uint64_t _peb=(__uint64_t)pinfo.PebBaseAddress;
        __uint64_t __api_set=_peb+0x68; // API_SET_NAMESPACE
        __uint64_t _api_set=0;
        ReadProcessMemory(
            proc,
            (void*)__api_set,
            &_api_set,
            sizeof(unsigned long long),
            NULL
        );
        if(_api_set==0)
            exit(1);
        __uint64_t _api_set_count=(__uint64_t)_api_set+(sizeof(unsigned long)*3);
        __uint64_t _api_set_entry_offset=(__uint64_t)_api_set+(sizeof(unsigned long)*4);
        
        unsigned long api_set_count=0;
        unsigned long entry_offset=0;
        if(!ReadProcessMemory(
            proc,
            (void*)_api_set_count,
            &api_set_count,
            sizeof(unsigned long),
            NULL
        ) || !ReadProcessMemory(
             proc,
            (void*)_api_set_entry_offset,
            &entry_offset,
            sizeof(unsigned long),
            NULL
        ))
        {
            printf("[-52] INJECTOR\n");
            exit(1);
        }

        __uint64_t entry=_api_set+entry_offset;

        printf("API SET COUNT IS %lu\n",api_set_count);
        // loop never reaches execution 
        for(unsigned long i=0;i<api_set_count;i++)
        {

           __uint64_t _api_set_name_offs=entry+sizeof(unsigned long);
           unsigned long api_set_name_offs=0;
           unsigned long name_length=0;
           if(!ReadProcessMemory(
                proc,
                (void*)_api_set_name_offs,
                &api_set_name_offs,
                sizeof(unsigned long),
                NULL
            ) || 
            !ReadProcessMemory(
                proc,
                (void*)(entry+(sizeof(unsigned long)*2)),
                &name_length,
                sizeof(unsigned long),
                NULL
            ))
            {
                printf("[-78] injec\n");
                exit(1);
            }

            size_t length=name_length/sizeof(wchar_t);

            wchar_t virtual_dll_name[length+1];
            virtual_dll_name[length]='\0';
            ReadProcessMemory(
                proc,
                (void*)(_api_set+api_set_name_offs),
                virtual_dll_name,
                name_length,
                NULL
            );

            // format is dll-some-name-x-y-z
            char virtual_dll_name_char[length+1];
            for(size_t i=0;i<=length;i++)
                if(i!=length)    
                    virtual_dll_name_char[i]=(char)(virtual_dll_name[i]);
                else
                    virtual_dll_name_char[i]='\0';
            
            // formt is dll_name-x-y-z (z should be ignored)
            // virtual dll  --> specific dll with specific build
            // it is better to compare hashes but leaving for simplicity
            // read notes on code. needs fix here
            if(!compare(targetDll,virtual_dll_name_char)){
                 entry+=sizeof(API_SET_NAMESPACE_ENTRY);
                 continue;
            }
            
            __uint64_t _value_offset=entry+(sizeof(unsigned long)*4);
            unsigned long dll_list_offset=0;
            unsigned long dll_count=0;

           if(!ReadProcessMemory(
                proc,
                (void*)_value_offset,
                &dll_list_offset,
                sizeof(unsigned long),
                NULL
            ) || 
            
            !ReadProcessMemory(
                proc,
                (void*)(entry+(sizeof(unsigned long)*5)),
                &dll_count,
                sizeof(unsigned long),
                NULL
            )
        )
        {
            printf("[-145] injector\n");
            exit(1);
        }

        // *is dll_list_offset offset from entry or base*
        __uint64_t _api_set_value_entry=(__uint64_t)(entry+dll_list_offset);
        for(unsigned int i=0;i<dll_count;i++){
          __uint64_t _og_dll_name_offs=(__uint64_t)(_api_set_value_entry+(sizeof(unsigned long)*3));
          unsigned long  og_dll_name_sz=0;
          __uint64_t og_dll_name_offs=0; // ?is this offset or actual address?

          if(!ReadProcessMemory(
                proc,
                (void*)_og_dll_name_offs,
                &og_dll_name_offs,
                sizeof(unsigned long),
                NULL
            ) || !ReadProcessMemory(
                    proc,
                    (void*)(_api_set_value_entry+(sizeof(unsigned long)*4)),
                    &og_dll_name_sz,
                    sizeof(unsigned long),
                    NULL
            ))
            {
                printf("[-170] injector\n");
                exit(1);
            }

            size_t og_dll_name_length=og_dll_name_sz/sizeof(wchar_t);
            wchar_t og_dll[og_dll_name_length+1];
            og_dll[og_dll_name_length]='\0';

            if(!ReadProcessMemory(
                proc,
                (void*)og_dll_name_offs,
                og_dll,
                og_dll_name_sz,
                NULL
            )){
                printf("[- 286] \n");
                exit(1);
            }

            char* real_dll=(char*)malloc(sizeof(char)*og_dll_name_length+1);
            real_dll[og_dll_name_length]='\0';
            for(size_t k=0;k<og_dll_name_length;k++)
                real_dll[k]=(char)(og_dll[k]);

            printf("---------------- %s maps to %s------------------\n",targetDll,real_dll);

            
            char** tmp=realloc(mappedDLls,sizeof(char*)*((*mappedDllsCount)+1));
            if(tmp!=NULL){
                mappedDLls=tmp;
                tmp=NULL;
            }
            ++(*mappedDllsCount);
            mappedDLls[*mappedDllsCount-1]=real_dll;

            _api_set_value_entry+=sizeof(API_SET_VALUE_ENTRY);

        }
            
        return mappedDLls;
    }
    return mappedDLls;

}

bool compare(char* vDll,char*vSystemDll){
    size_t len=strlen(vDll);
    bool lastCheck=false;
    if(strncasecmp(vDll,vSystemDll,len-1)==0)
        return true;
    return false;
}