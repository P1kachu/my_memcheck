#ifndef DEFINES_HH
# define DEFINES_HH

# include <map>
# include <string>
# include <vector>
# include <fstream>
# include <sstream>
# include <iostream>
# include <stdexcept>
# include <algorithm>

# include <link.h>
# include <stdio.h>
# include <fcntl.h>
# include <string.h>
# include <unistd.h>
# include <stdlib.h>
# include <sys/reg.h>
# include <sys/stat.h>
# include <sys/user.h>
# include <sys/wait.h>
# include <sys/mman.h>
# include <sys/auxv.h>
# include <sys/types.h>
# include <sys/ptrace.h>


# include "colors.hh"
# include "helpers.hh"

# define OUT stdout
# define UNUSED(x) { (x) = (x); }
# define BONUS 1


// mem_strace
# define NULL_STRING        "NULL"
# define MMAP_SYSCALL       9
# define MPROTECT_SYSCALL   10
# define MUNMAP_SYSCALL     11
# define BRK_SYSCALL        12
# define MREMAP_SYSCALL     25
# define CLONE_SYSCALL      56
# define FORK_SYSCALL       57
# define VFORK_SYSCALL      58
# define EXECVE_SYSCALL     59
# define EXIT_SYSCALL       60
# define EXIT_GROUP_SYSCALL 231
# define FOLLOW_FORK_MODE   PTRACE_O_TRACEFORK \
                          | PTRACE_O_TRACEVFORK \
                          | PTRACE_O_TRACECLONE \
                          | PTRACE_O_TRACEEXIT

# define TRAP_LEN    1
# define TRAP_INST   0xCC

# if defined(__i386)

#  define INSTR_REG   eip
#  define TRAP_MASK   0xFFFFFF00

# elif defined(__x86_64)

#  define INSTR_REG   rip
#  define TRAP_MASK   0xFFFFFFFFFFFFFF00

# endif /* !ARCH */

//mem_strace_hook





#endif /* !DEFINES_HH */
