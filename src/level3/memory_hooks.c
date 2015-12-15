#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include "shared.hh"
// http://elinux.org/images/b/b5/Elc2013_Kobayashi.pdf

static __thread int no_hook;

void* (*callocp)(size_t, size_t);
void* (*mallocp)(size_t);
void* (*reallocp)(void*, size_t);
void  (*freep)(void*);

static void __attribute__((constructor)) init(void)
{
        callocp   = (void* (*) (size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
        mallocp   = (void* (*) (size_t))         dlsym (RTLD_NEXT, "malloc");
        reallocp  = (void* (*) (void *, size_t)) dlsym (RTLD_NEXT, "realloc");
        freep     = (void  (*) (void *))         dlsym (RTLD_NEXT, "free");
}

void *malloc (size_t len)
{
        void *ret;

        if (no_hook)
                return (*mallocp)(len);

        no_hook = 1;
        fprintf(stdout, "malloc(%zu", len);
        ret = (*mallocp)(len);
        asm volatile ("int3" : : "a" (CUSTOM_SYSCALL_MALLOC));
        fprintf(stdout, ") -> %p\n", ret);
        no_hook = 0;
        return ret;
}

void *calloc (size_t n, size_t len)
{
        void *ret;
        if (no_hook)
        {
                if (callocp == NULL)
                {
                        //ret = my_calloc(n, len);
                        ret = calloc(n, len);
                        return ret;
                }
        }
        no_hook = 1;
        ret = (*callocp)(n, len);
        asm volatile ("int3" : : "a" (CUSTOM_SYSCALL_CALLOC));
        no_hook = 0;
        return ret;
}


void *realloc (void* ptr, size_t len)
{
        no_hook = 1;
        void* ret = (*reallocp)(ptr, len);
        asm volatile ("int3" : : "a" (CUSTOM_SYSCALL_REALLOC));
        no_hook = 0;
        return ret;
}


void free (void* ptr)
{
        no_hook = 1;
        (*freep)(ptr);
        asm volatile ("int3" : : "a" (CUSTOM_SYSCALL_FREE));
        no_hook = 0;
}
