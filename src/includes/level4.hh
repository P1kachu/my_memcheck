#ifndef LEVEL4_HH
# define LEVEL4_HH

# include "level2.hh"
# include "defines.hh"

// Play with pages PROT_* flags, to break everything \o/
int remove_page_protection(pid_t pid, Tracker& t);
int set_page_protection(unsigned long addr, size_t len,
                        unsigned long prot, pid_t pid);
int reset_page_protection(pid_t pid, Tracker& t);

// Catch segfaults and breakpoints, then call previous levels
int handle_injected_sigsegv(pid_t pid, Tracker& t);
int handle_injected_syscall(int syscall, Breaker& b, void* bp, Tracker& t);

// Check for invalid memory accesses
int sanity_customs(pid_t pid, Tracker& t, int handler);
int display_memory_leaks(Tracker& t);
int invalid_free(pid_t pid, void* pointer, Tracker& t);
#endif /* LEVEL4_HH */
