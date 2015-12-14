#include <unistd.h>
#include <dlfcn.h>
// http://elinux.org/images/b/b5/Elc2013_Kobayashi.pdf

static __thread int no_hook;

static void __attribute__((constructor)) init(void)
{
        callocp   = (void *(*) (size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
        mallocp   = (void *(*) (size_t))         dlsym (RTLD_NEXT, "malloc");
        reallocp  = (void *(*) (void *, size_t)) dlsym (RTLD_NEXT, "realloc");
        memalignp = (void *(*)(size_t, size_t))  dlsym (RTLD_NEXT, "memalign");
        freep     = (void (*) (void *))          dlsym (RTLD_NEXT, "free");
}

void *malloc (size_t len)
{
        void *ret;
        void *caller;
        if (no_hook)
        {
                return (*mallocp)(len);
        }
        no_hook = 1;
        caller = RETURN_ADDRESS(0);
        fprintf(OUT, "%p malloc(%zu", caller, len);
        ret = (*mallocp)(len);
        fprintf(OUT, ") -> %p\n", ret);
        no_hook = 0;
        return ret;
}
