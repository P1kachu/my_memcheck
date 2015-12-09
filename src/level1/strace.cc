#include "level1.hh"
#include "syscalls.hh"

/*static const char* get_syscall_name(int id)
{
}*/

static int wait_for_syscall(pid_t child)
{
  int status = 0;
  while (true)
  {
    // Trace system calls from child
    ptrace(PTRACE_SYSCALL, child, 0, 0);

    //       pid, status, options
    waitpid(child, &status, 0);

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
  char** args = new char*[argc + 1];
  memcpy(args, argv, argc * sizeof (char*));
  args[argc] = nullptr; // FIXME Ask ACU

  ptrace(PTRACE_TRACEME);
  kill(getpid(), SIGSTOP);
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
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

  while (true)
  {
    if (wait_for_syscall(child))
      break;


    // Retrieve data from $rax
    int syscall = ptrace(PTRACE_PEEKUSER, child, sizeof (long) * ORIG_RAX);

    print_syscall(child, syscall);


    int tmp = wait_for_syscall(child);
    retval = ptrace(PTRACE_PEEKUSER, child, sizeof (long) * RAX);
    fprintf(OUT, ") = %d\n", retval);

    if (tmp)
      break;

  }

  fprintf(OUT, "\n+++ Process %d exited with %d +++\n", child, retval);
  return 0;

}
