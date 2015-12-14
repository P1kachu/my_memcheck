#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

extern ElfW(Dyn) _DYNAMIC[];
# define print_errno()                                                                      \
        {                                                                                   \
                if (errno)                                                                  \
                {                                                                           \
                        fprintf(OUT, "%sERROR%s Something went wrong: %s (%s%s%s:%d)\n",    \
                                RED, NONE, strerror(errno), RED, __FILE__, NONE, __LINE__); \
                        exit(-1);                                                           \
                }                                                                           \
        }

int some_inline()
{
        printf("%s[C %d]%s Inline func\n", "\033[31;1m", getpid(), "\033[0m");

        char str[] = "ASM Inline !\n";
        long len = strlen(str);
        int ret = 0;

        asm volatile("movq $1, %%rax \n\t"
                "movq $1, %%rdi \n\t"
                "movq %1, %%rsi \n\t"
                "movl %2, %%edx \n\t"
                "syscall"
                : "=g"(ret)
                : "g"(str), "g" (len));

        printf("%s[C %d]%s /Inline func\n", "\033[31;1m", getpid(), "\033[0m");
        return ret;
}

int main()
{
  struct r_debug *r_debug = NULL;
  ElfW(Dyn)* dyn = _DYNAMIC;
  printf("%s[C %d]%s Child _DYNAMIC: %p\n", "\033[31;1m", getpid(), "\033[0m", (void*)dyn);
  for (; dyn->d_tag != DT_NULL; ++dyn)
  {
    //printf("size: %lu ", sizeof (ElfW(Dyn)));
    //printf("tag: %lu\n", dyn->d_tag);
    //printf("%p->%p\n", (void *) dyn, (void *) dyn->d_un.d_ptr);
    if (dyn->d_tag == DT_DEBUG)
    {
      //printf("TAG: %lu\n", dyn->d_tag);
      r_debug = (struct r_debug *) dyn->d_un.d_ptr;
      break;
    }
  }

  printf("%s[C %d]%s Child r_debug\t\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug);
  printf("%s[C %d]%s Child r_debug->r_brk\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_brk);
  printf("%s[C %d]%s Child r_debug->r_map\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_map);


  printf("%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m",
         mmap(0, 4096, 0, 34, -1, 0));



  printf("%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m",
         mmap(0, 27, 0, 34, -1, 0));


  printf("%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m",
         mmap(0, 20396, 0, 34, -1, 0));

  return some_inline();
}
