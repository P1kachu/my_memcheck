#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern ElfW(Dyn) _DYNAMIC[];
# define print_errno()                                                                      \
        {                                                                                   \
                if (errno)                                                                  \
                {                                                                           \
                        fprintf(OUT, "%sERROR%s Something went wrong: %s (%s%s%s:%d)\n", \
                                "\033[31;1m", "\033[0m", strerror(errno), "\033[31;1m", __FILE__, "\033[0m", __LINE__); \
                }                                                                           \
        }


int main()
{
  struct r_debug *r_debug = NULL;
  ElfW(Dyn)* dyn = _DYNAMIC;
  FILE* OUT = stderr;//fopen("/dev/null",0);
  fprintf(OUT, "\t%s[C %d]%s Child _DYNAMIC: %p\n", "\033[31;1m", getpid(), "\033[0m", (void*)dyn);
  for (; dyn->d_tag != DT_NULL; ++dyn)
  {
    if (dyn->d_tag == DT_DEBUG)
    {
      r_debug = (struct r_debug *) dyn->d_un.d_ptr;
      break;
    }
  }

  fprintf(OUT, "\t%s[C %d]%s Child r_debug\t\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug);
  fprintf(OUT, "\t%s[C %d]%s Child r_debug->r_brk\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_brk);
  fprintf(OUT, "\t%s[C %d]%s Child r_debug->r_map\t%p\n", "\033[31;1m", getpid(), "\033[0m", (void *) r_debug->r_map);


  fprintf(OUT, "\t%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m",
         mmap(0, 4096, 0, 34, -1, 0));

  sbrk(0);

  brk(0);

  brk((char*)sbrk(0) + 64);

  char* t = (char*)malloc(0x400);
  t = (char*)realloc(t, 0x600);
  fprintf(OUT,"%c", t[0x100]);
  fprintf(OUT,"%c", t[0x200]);
  fprintf(OUT,"%c", t[0x300]);
  fprintf(OUT,"%c", t[0x400]);
  fprintf(OUT,"%c", t[0x500]);
  fprintf(stdout,"INVALID\n");
  fprintf(OUT,"%c", t[0x600]);
  fprintf(OUT,"%c", t[0x700]);
  fprintf(OUT,"%c", t[0x800]);
  fprintf(OUT,"%c", t[0x800]);

  free(t);
  t = (char*)calloc(sizeof(char), 0x800);
  free(t);
  void* ttt = mmap(0, 27, 0, 34, -1, 0);
  fprintf(OUT, "\t%s[C %d]%s mmap = %p\n", "\033[31;1m", getpid(), "\033[0m", ttt);
  mprotect((void*)ttt, 20, PROT_EXEC);
  munmap((void*)ttt, 27);
  int b = t[0];
  b = t[37];
  fprintf(OUT,"%p", t + 5);
  fprintf(OUT,"%p", ttt);
  fprintf(OUT,"%p", (char*)ttt + 20);
  fprintf(OUT,"%p", (char*)ttt + 30);
  return 0;
}
