#include <link.h>
#include <unistd.h>
#include <stdio.h>

extern ElfW(Dyn) _DYNAMIC[];

int main()
{
  struct r_debug *r_debug = NULL;
  ElfW(Dyn)* dyn = _DYNAMIC;
  printf("%s[%d]%s Found _DYNAMIC:\t\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void*)dyn);
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

  printf("%s[%d]%s Child r_debug\t\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug);
  printf("%s[%d]%s Child r_debug->r_brk\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_brk);
  printf("%s[%d]%s Child r_debug->r_map\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_map);
}