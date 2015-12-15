#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include "shared.hh"
// http://elinux.org/images/b/b5/Elc2013_Kobayashi.pdf

void* malloc(size_t size)
{
        static void* (*my_malloc)(size_t) = NULL;
        printf("inside shared object...\n");
        if (!my_malloc)
                my_malloc = dlsym(RTLD_NEXT, "malloc");  /* returns the object reference for malloc */
        void *p = my_malloc(size);               /* call malloc() using function pointer my_malloc */
        asm volatile ("int3" : : "a" (CUSTOM_SYSCALL_CALLOC));
        return p;
}
