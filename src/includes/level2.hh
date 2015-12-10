#ifndef LEVEL2_HH
# define LEVEL2_HH

# include "defines.hh"

class Breaker
{
public:
  Breaker(std::string binary_name, pid_t pid);
  void remove_breakpoint(void* addr);
  void add_breakpoint(void* addr);

  void print_bps() const;

  std::map<void*, unsigned long> handled_syscalls;
  void* brk;
  pid_t pid;
  struct r_debug* r_deb;
  std::string name;
};

#endif /* LEVEL2_HH */
