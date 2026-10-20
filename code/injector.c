#include <windows.h>

// dll injee

extern char* injectDLL(P_LdrLoadDll LdrLoadDll,HANDLE proc,char* dll,char*** loadedDlls,size_t* count,bool manual){
    // objectives: 
    // inject dll to remote process
    // resolve IAT for injected dll
    // !: only dll loaded is ntdll.
    // think about possible ways to implement such dll injecion
    //
    char* searchDirectory="C:\\Windows\\System32\\";
    char* dll_file=calloc(strlen(searchDirectory)+strlen(dll)+1,sizeof(char));
    strcpy(dll_file,searchDirectory);
    strcat(dll_file,dll);
    if(!manual) 
    {
        void* dllNameRemote=VirtualAllocEx(
            proc,
            NULL,
            strlen(dll_file)+1,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        struct Args {
            wchar_t* pathToFile;
            unsigned long flags;
            PUNICODE_STRING moduleFileName;
            HANDLE* handle;

        };

        struct Args args;
        
        
    }
    else 
    {
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
    {
        // set api resolve. parse set api through peb.(target process)
        // catch to which dll api resolves to
        // check if resovled dll is loaded
        // if not, load. if loaded return base.
        printf("[-] REQUIRED DLL IS NOT PRESENT ON THE SYSTEM!\n");
        exit(1);
    }
    
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
    char* dllBase=mapRoutineX(proc,dll_mm,&dll_relloc);
    if(dllBase)
        printf("DLL: %s has been mapped successfully!/n",dll);

    // if(dll_relloc)
    //     rellocate(proc,dllBase,(void*)dll_mm.heapBase,(void*)dll_mm.preferedBase,dll_relloc);

    printf("updated loaded dll list:\n");
    // till this point works.

    syncLoadedDlls(dll,loadedDlls,count);
    dumpLoadedDlls(*loadedDlls,count);

    printf("is about to resolve IAT!\n");
    resolveIAT(proc,dllBase,loadedDlls,count);
    
    // return essential info for filling IAT for those image depending on this dll
    return dllBase;
}

}