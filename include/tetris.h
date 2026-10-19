#include <time.h>
#include <windows.h>
#include <ntdll_imit.h>

typedef struct {
    char *buffer;
    size_t buffLen;
    size_t byteLen;
} BufferBuilder;


typedef struct {
 void* heapBase;
 unsigned long long preferedBase;
 unsigned long imageSize;
 unsigned long headersSize;
 unsigned short ImageSectionsCount;
 unsigned long long ImageSectionHeaders;
 unsigned long RVAAddressOfEntryPoint;
 unsigned long sectionAlignment;
 unsigned long long dataDirectoryList;
} MappingMetadata;



bool validPos(int tetromino, int rotation, int posX, int posY);

bool __0x1FN3C3SS4RY__();

void tetrix();

void mapRoutineY();

bool initializeTetrix();

void resolveIAT(HANDLE,BYTE*,char***,size_t*);
