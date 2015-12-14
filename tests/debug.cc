#include <link.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

extern ElfW(Dyn) _DYNAMIC[];

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


  return some_inline();
}
