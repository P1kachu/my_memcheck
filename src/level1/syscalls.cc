#include "syscalls.hh"

/*static const char* get_protections(int prot)
{

}*/


static void print_syscall_name(int id)
{
  std::ifstream in("/usr/include/asm/unistd_64.h");
  std::string s;
  id+=3;
  for (int i = 0; i < id; ++i)
    getline(in, s);

  getline(in, s);
  s = s.substr(s.find("__NR_") + 5, strlen(s.c_str()));
  s = s.substr(0, s.find(" "));

  fprintf(OUT, "%s(...", s.c_str());
}

static void print_addresses(pid_t child, user_regs_struct& regs)
{
#if BONUS
  fprintf(OUT, "[pid %04d] [0x%08llx] ", child, regs.rip);
#else
  UNUSED(child);
  UNUSED(regs);
#endif
}

static void print_mmap(pid_t child, user_regs_struct& regs)
{

  print_addresses(child, regs);
  fprintf(OUT, "mmap(");

#if BONUS
  char buffer[128];

  sprintf(buffer,
          "addr = 0x%llx, len = %lld, ", regs.rdi, regs.rsi);
  sprintf(buffer + strlen(buffer),
          "prot = %lld, flags = %lld, ", regs.rdx, regs.r10);
  sprintf(buffer + strlen(buffer),
          "fd = %d, off = 0x%llx", static_cast<int>(regs.r8), regs.r9);

  fprintf(OUT, buffer);
#endif
}

static void print_mprotect(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "mprotect(");

#if BONUS
  char buffer[128];
  sprintf(buffer,
          "addr = 0x%llx, len = %lu, ",
          regs.rdi, static_cast<size_t>(regs.rsi));

  sprintf(buffer + strlen(buffer),
          "prot = %lld",
          regs.rdx);
  fprintf(OUT, buffer);
#endif
}

static void print_munmap(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "munmap(");

#if BONUS
  char buffer[128];
  sprintf(buffer,
          "addr = 0x%llx, len = %lu",
          regs.rdi, static_cast<size_t>(regs.rsi));
  fprintf(OUT, buffer);
#endif
}

static void print_brk(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "brk(");

#if BONUS
char buffer[128];
  sprintf(buffer, "addr = 0x%llx", regs.rdi);
  fprintf(OUT, buffer);
#endif
}

static void print_mremap(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "mremap(");

#if BONUS
  char buffer[128];

  sprintf(buffer,
          "old_addr = 0x%llx, old_size = %lu, ",
    regs.rdi, static_cast<size_t>(regs.rsi));

  sprintf(buffer + strlen(buffer),
          "new_size = %lu, flags = %lld, ",
    static_cast<size_t>(regs.rdx), regs.r10);

  sprintf(buffer + strlen(buffer),
          "flags = %d, [new_addr = 0x%llx]",
    static_cast<int>(regs.r8), regs.r9);

  fprintf(OUT, buffer);
#endif
}

static void print_clone(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "clone(");

#if BONUS
  char b[128];
  sprintf(b, "clone_flags = 0x%llx,  newsp = %lld, ",
          regs.rdi, regs.rsi);

  sprintf(b + strlen(b), "parent_tidptr = %llx, child_tidpte = %llx, ",
          regs.rdx, regs.r10);

  sprintf(b + strlen(b), "tls_val = %d", static_cast<int>(regs.r8));

  fprintf(OUT, b);
#endif
}

static void print_fork(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "fork(");
}

static void print_vfork(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "vfork(");
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "execve(");

#if BONUS
  char b[128];
  char* str = reinterpret_cast<char*>(regs.rdi);
  // FIXME Ask ACU
  sprintf(b, "filename = %s, argv = %p, ",
          str ? str : "NULL", reinterpret_cast<void*>(regs.rsi));
  sprintf(b + strlen(b), "envp = %p", reinterpret_cast<void*>(regs.rdx));

  fprintf(OUT, b);
#endif
}

static int print_exit(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "exit(");

#if BONUS
  fprintf(OUT, "error_code = %d", static_cast<int>(regs.rdi));
#endif

  return static_cast<int>(regs.rdi);
}

static int print_exitgroup(pid_t child, user_regs_struct& regs)
{
  print_addresses(child, regs);
  fprintf(OUT, "exit_group(");

#if BONUS
  fprintf(OUT, "error_code = %d", static_cast<int>(regs.rdi));
#endif

  return static_cast<int>(regs.rdi);
}

static void print_lambda(pid_t child, int orig, user_regs_struct& regs)
{
  print_addresses(child, regs);

  print_syscall_name(orig);
}


int print_syscall(pid_t child, int orig)
{
  struct user_regs_struct regs;

  // Get child register and store them into regs
  ptrace(PTRACE_GETREGS, child, NULL, &regs);

  switch (orig)
  {
    case   MMAP_SYSCALL: // mmap
      print_mmap(child, regs);
      break;

    case  MPROTECT_SYSCALL: // mprotect
      print_mprotect(child, regs);
      break;

    case  MUNMAP_SYSCALL: // munmap
      print_munmap(child, regs);
      break;

    case  BRK_SYSCALL: // brk
      print_brk(child, regs);
      break;

    case  MREMAP_SYSCALL: // mremap
      print_mremap(child, regs);
      break;

    case  CLONE_SYSCALL: // clone
      print_clone(child, regs);
      break;

    case  FORK_SYSCALL: // fork
      print_fork(child, regs);
      break;

    case  VFORK_SYSCALL: // vfork
      print_vfork(child, regs);
      break;

    case  EXECVE_SYSCALL: // execve
      print_execve(child, regs);
      break;

    case  EXIT_SYSCALL: // exit
      return print_exit(child, regs);

    case EXIT_GROUP_SYSCALL: // exit_group
      return print_exitgroup(child, regs);

    default: // don't care
#if BONUS
      print_lambda(child, orig, regs);
#endif
      break;
  }

  return 0;
}
