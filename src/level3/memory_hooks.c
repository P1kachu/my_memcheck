#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include "shared.hh"
// http://elinux.org/images/b/b5/Elc2013_Kobayashi.pdf

void* malloc(size_t size)
{
        static void* (*my_malloc)(size_t) = NULL;

	if (!my_malloc)
                my_malloc = dlsym(RTLD_NEXT, "malloc");

	void *p = my_malloc(size);

	asm volatile ("int3"
		      :
		      : "a" (CUSTOM_SYSCALL_MALLOC),
			"b" (p),
			"c" (size));

        return p;
}

void* calloc(size_t nmemb, size_t size)
{
        static void* (*my_calloc)(size_t, size_t) = NULL;

	if (!my_calloc)
                my_calloc = dlsym(RTLD_NEXT, "calloc");

	void *p = my_calloc(nmemb, size);

	asm volatile ("int3"
		      :
		      : "a" (CUSTOM_SYSCALL_CALLOC),
			"b" (p),
			"c" (size * nmemb));
        return p;
}

void* realloc(void* ptr, size_t size)
{
        static void* (*my_realloc)(void*, size_t) = NULL;

	if (!my_realloc)
                my_realloc = dlsym(RTLD_NEXT, "realloc");

	void *p = my_realloc(ptr, size);

	asm volatile ("int3"
		      :
		      : "a" (CUSTOM_SYSCALL_REALLOC),
			"b" (p),
			"c" (size),
			"d" (ptr));
        return p;
}

void free(void* ptr)
{
        static void* (*my_free)(void*) = NULL;

	if (!my_free)
                my_free = dlsym(RTLD_NEXT, "free");

	my_free(ptr);

	asm volatile ("int3"
		      :
		      : "a" (CUSTOM_SYSCALL_FREE),
			"b" (ptr));
}
