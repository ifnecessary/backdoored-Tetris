#!/bin/bash

x86_64-w64-mingw32-gcc -I ../include backdoor.c injector.c importResolver.c -o main.exe -lwininet 

