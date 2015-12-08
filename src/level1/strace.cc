#include "level1.hh"

const char* get_syscall_name(int id)
{

}

int run_child(int argc, char** argv)
{
  char* args[argc + 1];
  memcpy(args, argv, argc * sizeof (char*));
  args[argc] = NULL;

  ptrace(PTRACE_TRACEME);
  kill(getpid(), SIGSTOP);
  return execvp(args[0], args]);
}

int wait_for_syscall(pid_t child)
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

int trace_child(pid_t child)
{
  int status = 0;
  int retval = 0;
  fprintf(OUT, "[pid %d] ", child);
  waitpid(child, &status, 0);
  ptrace(PTRACE_SETOPTIONS, child, 0,
}
