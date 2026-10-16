#include <windows.h>


const char* test="saba\0";

int main(){
    HANDLE hFile = CreateFileW(
        L"C:\\Users\\Ana\\sabuki.txt",                   // File name
        GENERIC_WRITE,                    // Desired access (write)
        0,                                // Share mode (none/exclusive)
        NULL,                             // Security attributes
        CREATE_ALWAYS,                    // Creation disposition (overwrite if exists)
        FILE_ATTRIBUTE_NORMAL,            // File attributes
        NULL                              // Template file
    );

    return 0;
}