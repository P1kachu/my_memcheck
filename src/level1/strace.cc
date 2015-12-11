#include "level1.hh"
#include "syscalls.hh"

static int wait_for_syscall(pid_t child)
{
  int status = 0;
  while (true)
  {
    // Trace system calls from child
    if (ptrace(PTRACE_SYSCALL, child, 0, 0) == -1)
      fprintf(OUT, "%sERROR:%s PTRACE_SYSCALL failed\n", RED, NONE);

    //       pid, status, options
    waitpid(child, &status, __WALL);

    // Program was stopped by a signal and this signal is a syscall
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
      return 0;

    // Program exited normally
    if (WIFEXITED(status))
      return 1;
  }
}


int run_child(int argc, char** argv)
{
  char** args = new char* [argc + 1];
  memcpy(args, argv, argc * sizeof (char*));
  args[argc] = nullptr; // TODO : Ask ACU if this is clean

  if (ptrace(PTRACE_TRACEME) == -1)
    fprintf(OUT, "%sERROR:%s PTRACE_TRACEME failed\n", RED, NONE);

  int ret = execvp(args[0], args);
  delete[] args;
  return ret;
}


int trace_child(pid_t child)
{
  int status = 0;
  int retval = 0;
  waitpid(child, &status, 0);

  // PTRACE_O_TRACESYSGOOD is used to differentiate syscalls from normal traps
  if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD))
    fprintf(OUT, "%sERROR:%s PTRACE_O_TRACESYSGOOD failed\n", RED, NONE);

  // FOLLOW_FORK_MODE Bonus
  //if (ptrace(PTRACE_SETOPTIONS, child, 0, FOLLOW_FORK_MODE) == -1)
  //  fprintf(OUT, "%sERROR:%s FOLLOW_FORK_MODE failed\n", RED, NONE);
  // TODO : ASK ACU why the output disappear

  while (true)
  {

    if (wait_for_syscall(child))
      break;


    // Retrieve data from $rax
    int syscall = ptrace(PTRACE_PEEKUSER, child, sizeof (long) * ORIG_RAX);

    int rdi = print_syscall(child, syscall);

    int tmp = wait_for_syscall(child);
    retval = ptrace(PTRACE_PEEKUSER, child, sizeof (long) * RAX);

    if (retval >= 0)
      fprintf(OUT, ") = %d\n", retval);
    else
      fprintf(OUT, ") = ?\n");

    if (syscall == EXIT_SYSCALL || syscall == EXIT_GROUP_SYSCALL)
      retval = rdi;

    if (tmp)
      break;

  }

  fprintf(OUT, "\n+++ Process %d exited with %d+++\n", child, retval);
  return 0;

}
