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
                        printf("%sERROR%s Something went wrong: %s (%s%s%s:%d)\n",    \
                                "\033[31;1m", "\033[0m", strerror(errno), "\033[31;1m", __FILE__, "\033[0m", __LINE__); \
                }                                                                           \
        }


int main()
{
  struct r_debug *r_debug = NULL;
  ElfW(Dyn)* dyn = _DYNAMIC;
  printf("%s[C %d]%s Child _DYNAMIC: %p\n", "\033[31;1m", getpid(), "\033[0m", (void*)dyn);
  for (; dyn->d_tag != DT_NULL; ++dyn)
  {
    if (dyn->d_tag == DT_DEBUG)
    {
      r_debug = (struct r_debug *) dyn->d_un.d_ptr;
      break;
    }
  }

  printf("%s[C %d]%s Child r_debug\t\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug);
  printf("%s[C %d]%s Child r_debug->r_brk\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_brk);
  printf("%s[C %d]%s Child r_debug->r_map\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_map);


  printf("%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m",
         mmap(0, 4096, 0, 34, -1, 0));

  sbrk(0);

  brk(0);

  brk((char*)sbrk(0) + 64);

  void* ttt = mmap(0, 27, 0, 34, -1, 0);
  printf("%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m", ttt);

  munmap(ttt, 27);

  void* uuu = mmap(0, 20396, 0, 34, -1, 0);

  printf("%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m", uuu);


  uuu = mremap(uuu, 20396, 4096, 0, 0);
  mremap(uuu, 4096, 8192, 0, 0);
  return 0;
}
