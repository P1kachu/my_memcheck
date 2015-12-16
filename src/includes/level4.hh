#ifndef LEVEL4_HH
# define LEVEL4_HH

# include "level3.hh"

int remove_page_protection(pid_t pid, Tracker& t);
int set_page_protection(unsigned long addr, size_t len, unsigned long prot, pid_t pid);
int reset_page_protection(pid_t pid, Tracker& t);
int handle_injected_sigsegv(pid_t pid, Tracker& t, void* bp);
int handle_injected_syscall(int syscall, Breaker& b, void* bp, Tracker& t);

int sanity_check(pid_t pid, Tracker& t, void* segv_addr);

#endif /* LEVEL4_HH */
