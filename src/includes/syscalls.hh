#ifndef SYSCALLS_HH
# define SYSCALLS_HH

# include "defines.hh"

int print_retval(pid_t child);
int print_syscall(pid_t child, int orig);

#endif /* !SYSCALLS_HH */
