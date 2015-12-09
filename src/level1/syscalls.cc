#include "syscalls.hh"


static void print_mmap(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] mmap(", child, regs.rip);

#if BONUS
  fprintf(OUT, "addr = %lld, len = %lld, ", regs.rdi, regs.rsi);
  fprintf(OUT, "prot = %lld, flags = %lld, ", regs.rdx, regs.r10);
  fprintf(OUT, "fd = %lld, off = %lld", regs.r8, regs.r9);
#endif
}

static void print_mprotect(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] mprotect(", child, regs.rip);

#if BONUS
  fprintf(OUT, "addr = %lld, len = %lu, ", regs.rdi, regs.rsi);
  fprintf(OUT, "prot = %lld", regs.rdx);
#endif
}

static void print_munmap(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] munmap(", child, regs.rip);

#if BONUS
  fprintf(OUT, "addr = %lld, len = %lu", regs.rdi, regs.rsi);
#endif
}

static void print_brk(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] brk(", child, regs.rip);

#if BONUS
  fprintf(OUT, "addr = %lld", regs.rdi);
#endif
}

static void print_mremap(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] mremap(", child, regs.rip);

#if BONUS
  fprintf(OUT, "addr = %lld, len = %lu", regs.rdi, regs.rsi);
#endif
}

static void print_clone(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] clone(", child, regs.rip);
}

static void print_fork(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] fork(", child, regs.rip);
}

static void print_vfork(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] vfork(", child, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] execve(", child, regs.rip);
}

static void print_exit(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] exit(", child, regs.rip);
}

static void print_exitgroup(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] exit_group(", child, regs.rip);
}

static void print_lambda(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08llx] some_func(", child, regs.rip);
}


void print_syscall(pid_t child, int orig)
{
  struct user_regs_struct regs;

  // Get child register and store them into regs
  ptrace(PTRACE_GETREGS, child, NULL, &regs);



  switch (orig)
  {
    case   9: // mmap
      print_mmap(child, regs);
      break;

    case  10: // mprotect
      print_mprotect(child, regs);
      break;

    case  11: // munmap
      print_munmap(child, regs);
      break;

    case  12: // brk
      print_brk(child, regs);
      break;

    case  25: // mremap
      print_mremap(child, regs);
      break;

    case  56: // clone
      print_clone(child, regs);
      break;

    case  57: // fork
      print_fork(child, regs);
      break;

    case  58: // vfork
      print_vfork(child, regs);
      break;

    case  59: // execve
      print_execve(child, regs);
      break;

    case  60: // exit
      print_exit(child, regs);
      break;

    case 231: // exit_group
      print_exitgroup(child, regs);
      break;

    default: // don't care
      print_lambda(child, regs);
  }
}
