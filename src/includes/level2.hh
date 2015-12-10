#ifndef LEVEL2_HH
# define LEVEL2_HH

# include "defines.hh"

class Breaker
{
public:
  Breaker(pid_t pid);
  void remove_breakpoint(void* addr);
  void add_breakpoint(void* addr);

  void print_bps() const;

  std::map<void*, unsigned long> handled_syscalls;
  void* brk;
  pid_t pid;
  struct r_debug* r_deb;
};

#endif /* LEVEL2_HH */
