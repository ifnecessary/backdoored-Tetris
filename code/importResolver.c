#include <windows.h>
#include <string.h>
#include <ntdll_imit.h>
#include <tetris.h>
#include <stdio.h>
#include <stdbool.h>

// works for both main PE and loaded DLLs
extern void resolveIAT(HANDLE proc, PROCESS_BASIC_INFORMATION pinfo, BYTE *imageBase, DLL **loadedDlls, size_t *count, char *resolvingFor)
{
    unsigned long long e_lfanew = (unsigned long long)(imageBase + 0x3c);
    long e_lfanew_val = 0;
    ReadProcessMemory(
        proc,
        (void *)e_lfanew,
        &e_lfanew_val,
        sizeof(long),
        NULL);
    unsigned long long nt_headers = (unsigned long long)(imageBase + e_lfanew_val);
    unsigned long long opt_headers = (unsigned long long)(nt_headers + 0x18);
    unsigned long long dataDirectoryList = (unsigned long long)(opt_headers + 0x70);

    unsigned long long import_data_directory = (dataDirectoryList + (8 * IMAGE_DIRECTORY_ENTRY_IMPORT));
    unsigned long va_image_import_descriptor = 0;
    ReadProcessMemory(
        proc,
        (void *)(import_data_directory),
        &va_image_import_descriptor,
        sizeof(unsigned int),
        NULL);

    unsigned long long image_import_descriptor = (unsigned long long)(imageBase + va_image_import_descriptor);

    // l through imports to resolve
    while (true)
    {
        unsigned long rva_thunk = 0;
        unsigned long rva_iat = 0;
        unsigned long rva_name = 0;
        ReadProcessMemory(
            proc,
            (void *)(image_import_descriptor),
            &rva_thunk,
            sizeof(unsigned long),
            NULL);
        ReadProcessMemory(
            proc,
            (void *)(image_import_descriptor + 16),
            &rva_iat,
            sizeof(unsigned long),
            NULL);

        if (rva_thunk == 0 || rva_iat == 0)
            break;

        ReadProcessMemory(
            proc,
            (void *)(image_import_descriptor + 12),
            &rva_name,
            sizeof(unsigned long),
            NULL);

        unsigned long long import_lookup_table = (unsigned long long)(imageBase + rva_thunk);
        unsigned long long import_address_table = (unsigned long long)(imageBase + rva_iat);
        unsigned long long dll_name = (unsigned long long)(imageBase + rva_name);

        char c = 'x';
        int read = 0;
        char *__dll__name = calloc(260, 1);
        while (read < 259)
        {
            ReadProcessMemory(
                proc,
                (void *)(dll_name + read),
                &c,
                sizeof(char),
                NULL);
            *(__dll__name + read) = c;
            ++read;
            if (c == 0)
                break;
        }
        char *_tmp = realloc(__dll__name, read);
        if (_tmp != NULL)
        {
            __dll__name = _tmp;
            _tmp = NULL;
        }

        // dll name format is: name.dll
        lowercase(__dll__name);
        printf("Resolving for: %s Working on DLL: %s\n", resolvingFor, __dll__name);

        // analyze the flow
        DLL *__loaded_dll__ = isDllLoaded(__dll__name, *loadedDlls, count);
        if (__loaded_dll__)
        {
            resolveCore(
                proc,
                (__uint64_t)(__loaded_dll__->dll_base),
                (__uint64_t)imageBase,
                import_address_table,
                import_lookup_table,
                __loaded_dll__->exportDirBase);
            printf("-");
        }
        else
        {
            printf("%s is not loaded so injectDLL()\n", __dll__name);
            int injectedCount = 0;
            // for dlls <--> virtual dll, injectdll must return list of real injected dll(s)(might be >1).
            __uint64_t __injected__ = injectDLL(proc, pinfo, __dll__name, loadedDlls, count, &injectedCount);
            if (injectedCount == 1)
            {
                // resolving classic dll
                DLL *_x_ = (DLL *)__injected__;
                resolveCore(
                    proc,
                    _x_->dll_base,
                    (__uint64_t)imageBase,
                    import_address_table,
                    import_lookup_table,
                    _x_->exportDirBase);
            }
            else if (injectedCount > 1)
            {
                // resolving classic dll list derived from api set virtual dlls
                DLL **_x_ = (DLL **)__injected__;
                resolveVirtuals(
                    proc,
                    import_address_table,
                    import_lookup_table,
                    imageBase,
                    _x_,
                    injectedCount);
            }
        }

        image_import_descriptor += 20; // each descriptor = 20 bytes
    }
}

// optimization is mandatory
void resolveCore(
    HANDLE proc,
    __uint64_t exporterDllBase,  // DLL base which exports functions
    __uint64_t importerDllBase,  // PE/DLL base which is about to import functions
    __uint64_t imp_addr_table,   // iat
    __uint64_t imp_lookup_table, // list of 8 byte integers
    __uint64_t exportDirectory)  // exp dir
{

    DWORD numberOfNames = (DWORD)readRemMem(proc, exportDirectory + 24, sizeof(DWORD));
    __uint64_t eat = exporterDllBase + (DWORD)readRemMem(proc, exportDirectory + 28, sizeof(DWORD));
    __uint64_t ent = exporterDllBase + (DWORD)readRemMem(proc, exportDirectory + 32, sizeof(DWORD));
    __uint64_t nameOrdinals = exporterDllBase + (DWORD)readRemMem(proc, exportDirectory + 36, sizeof(DWORD));

    int lookup_index = 0;
    while (1)
    {
        printf("resolve core executing!\n");
        __uint64_t imp_slot = imp_addr_table + lookup_index * sizeof(unsigned long long);
        long long lookup_entry = 0;
        ReadProcessMemory(
            proc,
            (void *)(imp_lookup_table + lookup_index * sizeof(long long)),
            &lookup_entry,
            sizeof(long long),
            NULL);

        if (!lookup_entry)
        {
            printf("look up entry value: %ll\n", lookup_entry);
            break;
        }
        // checking look up type: by name or by ordinal
        if (lookup_entry & 0x8000000000000000ULL)
        {
            // by ordinal
            printf("resolving by ordinal\n");
            WORD ordinal = (WORD)(lookup_entry & 0xFFFF);
            DWORD starting_ordinal = 0;
            ReadProcessMemory(
                proc,
                (void *)(exportDirectory + 16),
                &starting_ordinal,
                sizeof(DWORD),
                NULL);
            DWORD position = ordinal - starting_ordinal;
            // into consideration wether it is forwarder
            DWORD func_rva = (DWORD)readRemMem(proc, eat + position * sizeof(DWORD), sizeof(DWORD));
            __uint64_t func_abs = exporterDllBase + func_rva;
            WriteProcessMemory(
                proc,
                (void *)imp_slot,
                &func_abs,
                sizeof(__uint64_t),
                NULL);
            // resolved
        }
        else
        {
            // by name
            // rva to {word hint,dword name}
            printf("resolving by name\n");
            DWORD rva = (DWORD)(lookup_entry & 0xFFFFFFFFULL);
            __uint64_t imp_by_name_obj = importerDllBase + rva; // {word hint,char* name};
            // hint is optimiztation for lookup / index n exp_name_table
            WORD hint = (WORD)readRemMem(proc, (__uint64_t)imp_by_name_obj, sizeof(WORD));
            char importedProcedureName[128] = {0};
            ReadRemoteString(proc, (__uint64_t)(imp_by_name_obj + 2), importedProcedureName);
            printf("[RESOLVING!] WORKING TO RESOLVE IMPORTED FUNCTION: %s\n", importedProcedureName);
            // first try resolving by hint. if not then by name. later implement imp by forwarder handler
            DWORD nameRva = 0;
            char exportedProcedureName[128] = {0};
            DWORD exp_lookup_index = 0;
            if (hint < numberOfNames)
            {
                nameRva = (DWORD)readRemMem(proc, ent + hint * sizeof(DWORD), sizeof(DWORD));
                ReadRemoteString(proc, exporterDllBase + nameRva, exportedProcedureName);
                printf("vadareb by HINT: %s -- %s\n", importedProcedureName, exportedProcedureName);
                if (strcasecmp(importedProcedureName, exportedProcedureName) == 0)
                    exp_lookup_index = hint;
            }

            if (!exp_lookup_index)
                for (DWORD i = 0; i < numberOfNames; i++)
                {
                    nameRva = (DWORD)readRemMem(proc, ent + i * sizeof(DWORD), sizeof(DWORD));
                    // read remote string requires update
                    ReadRemoteString(proc, exporterDllBase + nameRva, exportedProcedureName);
                    // in consideration: forwarded chain case
                    printf("%s vadareb exported %s\n", importedProcedureName, exportedProcedureName);
                    // switch to binary comparison
                    if (strcasecmp(importedProcedureName, exportedProcedureName) != 0)
                        continue;
                    exp_lookup_index = i;
                    break;
                }

            if (!exp_lookup_index)
            {
                // if working on list of dlls and dll is not last ignore
                // if last or only one, throw error
                printf("resolve does not exist for %s\n", importedProcedureName);
                // break;
            }
            WORD ordinal = (WORD)readRemMem(proc, nameOrdinals + exp_lookup_index * sizeof(WORD), sizeof(WORD));
            DWORD func_rva = (DWORD)readRemMem(proc, eat + ordinal * sizeof(DWORD), sizeof(DWORD));
            __uint64_t func_abs = exporterDllBase + func_rva;
            if (!WriteProcessMemory(
                    proc,
                    (void *)imp_slot,
                    &func_abs,
                    sizeof(__uint64_t),
                    NULL))
            {
                printf("FAILED TO RESOLVE, ERROR CODE: %llu\n", GetLastError());
                exit(1);
            }
            printf("FUNCTION: %s has been resolved successfully. mapping is %s\n!", importedProcedureName, exportedProcedureName);

            // resolved
        }

        lookup_index++;
    }
}

void resolveVirtuals(
    HANDLE proc,
    __uint64_t imp_addr_table,
    __uint64_t imp_lookup_table,
    BYTE *imageBase,
    DLL **injected_ls,
    int injected_c)
{

    for (int k = 0; k < injected_c; k++)
    {
        __uint64_t dll_base = injected_ls[k]->dll_base;
        __uint64_t expDirBase = injected_ls[k]->exportDirBase;
        resolveCore(
            proc,
            dll_base,
            (__uint64_t)imageBase,
            imp_addr_table,
            imp_lookup_table,
            expDirBase);
    }
}