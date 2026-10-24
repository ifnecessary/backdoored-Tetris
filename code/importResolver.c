#include <windows.h>
#include <ntdll_imit.h>
#include <tetris.h>
#include <stdio.h>

// works for both main PE and loaded DLLs
extern void resolveIAT(HANDLE proc,PROCESS_BASIC_INFORMATION pinfo, BYTE* imageBase,char*** loadedDlls,size_t* count){
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
        printf("working on DLL: %s\n",__dll__name);
       
        if(isDllLoaded(__dll__name,*loadedDlls,count))
        {
            // this block is only being executed
            // for ntdll.
            // unsigned long long table=(unsigned long long)extractDllExportTable();
            // // apply IAT resolving
            __uint64_t expTable=extractImageExportTable();
            // resolve()

        }
        else
        {
            printf("%s is not loaded so injectDLL()\n",__dll__name);
            int exportedDirBaseCount=0;
            __uint64_t* exportDirBases=injectDLL(proc,pinfo,__dll__name,loadedDlls,count,&exportedDirBaseCount);
            for(int __0x0x0xBOOOOOOO=0;__0x0x0xBOOOOOOO<exportedDirBaseCount;__0x0x0xBOOOOOOO++){
                if(exportDirBases[__0x0x0xBOOOOOOO]==0)
                    continue;
                __uint64_t expTable=exportDirBases[__0x0x0xBOOOOOOO];
                // resolve()
            }
        }

        import_descriptor+=20;
    }


}
