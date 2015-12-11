#include <link.h>
#include <unistd.h>
#include <stdio.h>

extern ElfW(Dyn) _DYNAMIC[];

int main()
{
  printf("\nPid %d\n", getpid());
  struct r_debug *r_debug = NULL;
  ElfW(Dyn)* dyn = _DYNAMIC;
  printf("Child 2 Dyn: %p\n", (void*)dyn);
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

  printf("Child r_debug %p\n", (void *) r_debug);
}
