#!/bin/sh

find . \( \
     -name "._bckp*" \
     -name "*.bckp" \
     -o  -name "*.o" \
     -o  -name "CMakeCache.txt" \
     -o  -name "CMakeFiles" \
     -o -name "Makefile" \
     -o -name "cmake_install.cmake" \
     -o  -name ".gdb_history" \
     -o  -name "peda*" \
     -o  -name "CSR*" \
     -o -name "*.a" \
     -o -name "*~" \
     -o -name "build" \
     -o  -name "*.so" \
     -o -name "42sh" \
     -o  -name "__pycache__" \
     \) -print -exec rm -rf {} \;
exit 0
