#ifndef LEVEL2_HH
# define LEVEL2_HH

# include "defines.hh"

class Breaker
{
public:
  Breaker(pid_t pid);

  std::vector<void*> handled_syscalls;
  ElfW(Addr) brk;
  pid_t pid;
  struct r_debug* r_deb;
};

#endif /* LEVEL2_HH */
