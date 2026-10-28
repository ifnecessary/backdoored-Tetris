#include <windows.h>
#include <ntdll_imit.h>
#include <tetris.h>
#include <stdio.h>

// works for both main PE and loaded DLLs
extern void resolveIAT(HANDLE proc,PROCESS_BASIC_INFORMATION pinfo, BYTE* imageBase,DLL** loadedDlls,size_t* count,char* resolvingFor){
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
    
    // l through imports to resolve
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
        char *__dll__name=calloc(260,1);
        while(read<259){
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
        int length=0;
        for(int i=0;i<260;i++){
            length++;
            if(__dll__name[i]==0)
                break;
        }
        char* _tmp=realloc(__dll__name,length);
        if(_tmp!=NULL){
            __dll__name=_tmp;
            _tmp=NULL;
        }

        // dll name format is: name.dll
        lowercase(__dll__name);
        printf("Resolving for: %s Working on DLL: %s\n",resolvingFor,__dll__name);
       
        // import_name_table *
        // import_address_table *
        DLL *__loaded_dll__=isDllLoaded(__dll__name,*loadedDlls,count);
        if(__loaded_dll__)
            resolveCore(
                proc,
                (__uint64_t)(__loaded_dll__->dll_base),
                (__uint64_t)imageBase,
                import_address_table,
                import_name_table,
                __loaded_dll__->exportDirBase
            );
        else
        {
            printf("%s is not loaded so injectDLL()\n",__dll__name);
            int injectedCount=0;
            // for dlls <--> virtual dll, injectdll must return list of real injected dll(s)(might be >1).
            __uint64_t __injected__ =injectDLL(proc,pinfo,__dll__name,loadedDlls,count,&injectedCount);
            if(injectedCount==1)
            {
                // resolving classic dll
                DLL* _x_=(DLL*)__injected__;
            }
            else if(injectedCount>1){
                // resolving classic dll list given by api set virtual dlls
                DLL** _x_=(DLL**)__injected__;

            }
        }

        import_descriptor+=20;
    }


}


void resolveCore(
    HANDLE proc,
    __uint64_t imageBase, // export source
    __uint64_t imageBase_imports, // import source
    __uint64_t imp_addr_table,
    __uint64_t imp_name_table,
    __uint64_t exportDirBase
)
{
    // imp_name_table is list of rvas. 
    // each rva (from base of image contain iat) to struct {word hint; char* name}
    // imp_addr_table is list of slots where addr of function should be written
    // export dir base {rva,size} rva to IMAGE_EXPORT_DIRECTORY STRUCTUE

    // export dir
    // vergiliusproject.com
   __uint64_t  _funcNamesCount=(exportDirBase+24);
   DWORD funcNamesCount=0;
   ReadProcessMemory(
    proc,
    (void*)_funcNamesCount,
    &funcNamesCount,
    sizeof(DWORD),
    NULL
   );

   __uint64_t  _rva_addr_names=(exportDirBase+32);
   DWORD rva_addr_names=0;
   ReadProcessMemory(
    proc,
    (void*)_rva_addr_names,
    &rva_addr_names,
    sizeof(DWORD),
    NULL
   );
   __uint64_t _rva_addr_name_ordinals=(exportDirBase+36);
   DWORD rva_addr_name_ordinals=0;
   ReadProcessMemory(
    proc,
    (void*)_rva_addr_name_ordinals,
    &rva_addr_name_ordinals,
    sizeof(DWORD),
    NULL
   );

   __uint64_t _rva_addr_functions=(exportDirBase+28);
   DWORD rva_addr_functions=0;
   ReadProcessMemory(
    proc,
    (void*)_rva_addr_functions,
    &rva_addr_functions,
    sizeof(DWORD),
    NULL
   );


   // exports 
   __uint64_t functionNamesList=(__uint64_t)(imageBase+rva_addr_names);
   __uint64_t ordinalsNameList=(__uint64_t)(imageBase+rva_addr_name_ordinals);
   __uint64_t functionsAddrList=(__uint64_t)(imageBase+rva_addr_functions);




}