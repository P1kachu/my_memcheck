#include "syscalls.hh"


static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}

static void print_execve(pid_t child, user_regs_struct& regs)
{
  fprintf(OUT, "[pid %04d] [0x%08lx] execve()\n", pid, regs.rip);
}


void print_syscall(pid_t child, int orig)
{
  struct user_regs_struct regs;

  // Get child register and store them into regs
  ptrace(PTRACE_GETREGS, child, NULL, &regs);

  switch (orig)
  {
    case 09: // mmap
      print_mmap(child, regs);
      break;

    case 10: // mprotect
      print_mprotect(child, regs);
      break;

    case 11: // munmap
      print_munmap(child, regs);
      break;

    case 12: // brk
      print_brk(child, regs);
      break;

    case 25: // mremap
      print_mremap(child, regs);
      break;

    case 56: // clone
      print_clone(child, regs);
      break;

    case 57: // fork
      print_fork(child, regs);
      break;

    case 58: // vfork
      print_vfork(child, regs);
      break;

    case 59: // execve
      print_execve(child, regs);
      break;

    case 60: // exit
      print_exit(child, regs);
      break;

    case 231: // exit
      print_exitgroup(child, regs);
      break;

    default: // don't care
      print_lambda(child, regs);
  }
}
