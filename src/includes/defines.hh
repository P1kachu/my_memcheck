#ifndef DEFINES_HH
# define DEFINES_HH

/*
** Dirty to look at but easier to manage at the end
** Every define should be here
** Classes are here when I have no choice (else
** I would have put them into their own header)
*/

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
# include <errno.h>
# include <string.h>
# include <unistd.h>
# include <stdlib.h>
# include <sys/reg.h>
# include <sys/uio.h>
# include <sys/stat.h>
# include <sys/user.h>
# include <sys/wait.h>
# include <sys/mman.h>
# include <sys/auxv.h>
# include <sys/types.h>
# include <sys/ptrace.h>
# include <capstone/capstone.h>

# include "colors.hh"
# include "helpers.hh"
# include "syscalls.hh"

# define OUT stdout
# define UNUSED(x) { (x) = (x); }
# define BONUS 1
# define print_errno()                                                                      \
        {                                                                                   \
                if (errno)                                                                  \
                {                                                                           \
                        fprintf(OUT, "%sERROR%s Something went wrong: %s (%s%s%s:%d)\n",    \
                                RED, NONE, strerror(errno), RED, __FILE__, NONE, __LINE__); \
                        exit(-1);                                                           \
                }                                                                           \
        }

# define MAIN_CHILD         "origins"
# define NULL_STRING        "NULL"
# define MAX_STRING_SIZE    255
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
# define FOLLOW_FORK_MODE   PTRACE_O_TRACEFORK  \
        | PTRACE_O_TRACEVFORK                   \
        | PTRACE_O_TRACECLONE                   \
        | PTRACE_O_TRACEEXIT

# define TRAP_LEN    1
# define TRAP_INST   0xCC

# if defined(__i386)

#  define INSTR_REG   EIP
#  define XIP         eip
#  define XAX         eax
#  define TRAP_MASK   0xFFFFFF00

# elif defined(__x86_64)

#  define INSTR_REG   RIP
#  define XIP         rip
#  define XAX         rax
#  define TRAP_MASK   0xFFFFFFFFFFFFFF00

# endif /* !ARCH */



// Circular dependency...

class Breaker
{
public:
        Breaker(std::string binary_name, pid_t pid);
        struct r_debug* get_r_debug(pid_t pid);
        void remove_breakpoint(std::string, void* addr);
        void add_breakpoint(std::string, void* addr);
        ssize_t find_syscalls(void* addr);
        char is_from_us(void* addr) const;
        void handle_bp(void* addr);
        void exec_breakpoint(std::string region, void* addr);
        void print_bps() const;
        void reset_libs(void* link_map);

        // Vars
        std::map<std::string, std::map<void*, unsigned long>> handled_syscalls;
        void* rr_brk;
        pid_t pid;
        struct r_debug* r_deb;
        std::string name;
        void* program_entry_point;
};



#endif /* !DEFINES_HH */
