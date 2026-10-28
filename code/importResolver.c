#include <windows.h>
#include <string.h>
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
        *(__dll__name+read)=c;
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
       
        // analyze the flow
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
                resolveCore(
                    proc,
                    _x_->dll_base,
                    (__uint64_t)imageBase,
                    import_address_table,
                    import_name_table,
                    _x_->exportDirBase  
                );
            }
            else if(injectedCount>1){
                // resolving classic dll list given by api set virtual dlls
                DLL** _x_=(DLL**)__injected__;
                resolveVirtuals(
                    proc,
                    import_address_table,
                    import_name_table,
                    imageBase,
                    _x_,
                    injectedCount
                );
            }
        }

        import_descriptor+=20;
    }

}


bool resolveCore(
    HANDLE proc,
    __uint64_t imageBase, // export source
    __uint64_t imageBase_imports, // import source
    __uint64_t imp_addr_table,
    __uint64_t imp_name_table,
    __uint64_t exportDirBase
)
{

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
   __uint64_t functionNamesList=(__uint64_t)(imageBase+rva_addr_names); // ls of rva s 
   __uint64_t ordinalsNameList=(__uint64_t)(imageBase+rva_addr_name_ordinals); 
   __uint64_t functionsAddrList=(__uint64_t)(imageBase+rva_addr_functions); // ls of rvas

   __uint64_t offset=imp_name_table;
   int index=0;
   while(true){
    __uint64_t slot=imp_addr_table+index;
    unsigned int rva_to_name=0; // rva to {word hint, char*name}
    if(!ReadProcessMemory(
        proc,
        (void*)(offset), // +index?
        &rva_to_name.
        sizeof(unsigned int),
        NULL
    ))
        exit(1);
    if(!rva_to_name)
        break;
    __uint64_t _hint=imageBase_imports+rva_to_name; // {word,char*}
    WORD hint=0; // useful in export
    ReadProcessMemory(
        proc,
        (void*)_hint,
        &hint,
        sizeof(WORD),
        NULL
    );
    if(!hint)
        exit(1);
    __uint64_t _name=imageBase_imports+rva_to_name+sizeof(WORD);
    char nameStr[128];
    ReadRemoteString(proc,_name,nameStr);
    
  __uint64_t __exp_func_name_rva=functionNamesList+hint; // ls of rvas
  __uint64_t exp_func_name_rva=0;
  ReadProcessMemory(
    proc,
    (void*)__exp_func_name_rva,
    &exp_func_name_rva,
    sizeof(DWORD),
    NULL
  );

  __uint64_t targFuncNameBaseRemote=imageBase+exp_func_name_rva;
  char targetFuncName[128];
  ReadRemoteString(proc,targFuncNameBaseRemote,targetFuncName);

  if(strcmp(nameStr,targetFuncName)!=0)
    return false;

  
  WORD indexToAddrList=0;
  ReadProcessMemory(
    proc,
    (void*)(ordinalsNameList+hint),
    &indexToAddrList,
    sizeof(WORD),
    NULL
  );

  DWORD funcAddrRva=0;
  ReadProcessMemory(
    proc,
    (void*)(functionsAddrList+indexToAddrList),
    &funcAddrRva,
    sizeof(DWORD),
    NULL
);
  __uint64_t funcAddr=0;
  ReadProcessMemory(
    proc,
    (void*)(imageBase+funcAddrRva),
    &funcAddr,
    sizeof(unsigned long long),
    NULL
  );

  if(!funcAddr || !funcAddrRva || !indexToAddrList){
    printf("[-] 305\n");
    exit(1);
  }

  WriteProcessMemory(
    proc,
    (void*)slot,
    &funcAddr,
    sizeof(unsigned long long),
    NULL
  );
    
  printf("resolved function %s\n",nameStr);

  offset+=sizeof(DWORD);
  index++;
}
   


}



void resolveVirtuals(
    HANDLE proc,
    __uint64_t imp_addr_table,
    __uint64_t imp_name_table,
    BYTE* imageBase,
    DLL** injected_ls,
    int injected_c
){

    for(int k=0;k<injected_c;k++){
        char* dllName=injected_ls[k]->dll_name;
        __uint64_t dll_base=injected_ls[k]->dll_base;
        __uint64_t expDirBase=injected_ls[k]->exportDirBase;
        

    }
}