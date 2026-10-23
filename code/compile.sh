#!/bin/bash

x86_64-w64-mingw32-gcc -I ../include backdoor.c -o backdoor.exe -lwininet -lkernel32 -static-libgcc 

x86_64-w64-mingw32-g++ payload.c -o payload.exe -static-libstdc++
