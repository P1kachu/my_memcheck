#ifndef SYSCALLS_HH
# define SYSCALLS_HH

# include "defines.hh"

// Well... I should stop documenting the obvious
int print_retval(pid_t child, int syscall);
int print_syscall(pid_t child, int orig);

#endif /* !SYSCALLS_HH */
