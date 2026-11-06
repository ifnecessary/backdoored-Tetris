#include <windows.h>
#include <stdio.h>

int sane(void)
{
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    char process[] = "notepad.exe";
    BOOL ok = CreateProcess(
        NULL,    // application name (NULL = use command line)
        process, // command line (must be writable buffer, not const)
        NULL,    // process security attributes
        NULL,    // thread security attributes
        FALSE,   // inherit handles
        0,       // creation flags
        NULL,    // environment (NULL = inherit parent's)
        NULL,    // current directory (NULL = inherit parent's)
        &si,
        &pi);

    if (!ok)
    {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Spawned notepad.exe, PID = %lu\n", pi.dwProcessId);

    // optional: wait for it to exit
    // WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}