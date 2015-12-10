#include "level2.hh"

int main()
{
  pid_t pid = 0;

  if ((pid = fork()))
  {
    ptrace(PTRACE_ATTACH, pid, 0, 0);
    Breaker b(pid);
    b.add_breakpoint(b.brk);
    b.print_bps();
    b.remove_breakpoint(b.brk);
  }
}
