#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
// http://elinux.org/images/b/b5/Elc2013_Kobayashi.pdf

static __thread int no_hook;

void* (*callocp)(size_t, size_t);
void* (*mallocp)(size_t);
void* (*reallocp)(void*, size_t);
void* (*memalignp)(size_t, size_t);
void  (*freep)(void*);
static void __attribute__((constructor)) init(void)
{
        callocp   = (void* (*) (size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
        mallocp   = (void* (*) (size_t))         dlsym (RTLD_NEXT, "malloc");
        reallocp  = (void* (*) (void *, size_t)) dlsym (RTLD_NEXT, "realloc");
        memalignp = (void* (*) (size_t, size_t)) dlsym (RTLD_NEXT, "memalign");
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
        fprintf(stdout, ") -> %p\n", ret);
        no_hook = 0;
        return ret;
}
