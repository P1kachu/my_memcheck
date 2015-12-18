#ifndef DEFINES_HH
# define DEFINES_HH

/*
** Dirty to look at but easier to manage at the end
** Every define should be here
** Classes are here when I have no choice (else
** I would have put them into their own header)
*/


/* Includes for the whole project */
# include <map>
# include <list>
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
# include <signal.h>

# include "colors.hh"
# include "shared.hh"
# include "helpers.hh"
# include "syscalls.hh"

/* Macros */
# define OUT                      stdout
# define MAIN_CHILD               "origins"
# define NULL_STRING              "NULL"
# define CUSTOM_BREAKPOINT         -3
# define SYSCALL_ERROR             -2
# define NO_SYSCALL                -1
# define BONUS                     1
# define MMAP_SYSCALL              9
# define MPROTECT_SYSCALL          10
# define MUNMAP_SYSCALL            11
# define BRK_SYSCALL               12
# define MREMAP_SYSCALL            25
# define CLONE_SYSCALL             56
# define FORK_SYSCALL              57
# define VFORK_SYSCALL             58
# define EXECVE_SYSCALL            59
# define EXIT_SYSCALL              60
# define EXIT_GROUP_SYSCALL        231
# define MAX_STRING_SIZE           255
# define NOT_FOUND                 404
# define TRAP_LEN                  1
# define TRAP_INST                 0xCC
# define MALLOC_CHILD              0xdeadbeef
# define SYSCALL                   0x050f
//# define IS_DEBUG                  1

# if defined(__i386)

#  define INSTR_REG   EIP
#  define XAX         eax
#  define XIP         eip
#  define O_XAX       ORIG_EAX
#  define P_XAX       EAX
#  define TRAP_MASK   0xFFFFFF00

# elif defined(__x86_64)

#  define INSTR_REG   RIP
#  define XAX         rax
#  define XIP         rip
#  define O_XAX       ORIG_RAX
#  define P_XAX       RAX
#  define TRAP_MASK   0xFFFFFFFFFFFFFF00

# endif /* !ARCH */


/* "Functions" */
# define UNUSED(x) { (x) = (x); }
# define print_errno()                                                                      \
        {                                                                                   \
                if (errno)                                                                  \
                {                                                                           \
                        fprintf(OUT, "%sERROR%s Something went wrong: %s (%s%s%s:%d)\n",    \
                                RED, NONE, strerror(errno), RED, __FILE__, NONE, __LINE__); \
                        exit(-1);                                                           \
                }                                                                           \
        }
# define get_orig_xax(pid) { ptrace(PTRACE_PEEKUSER, pid, sizeof (long) * O_XAX) }
# define get_xax(pid) { ptrace(PTRACE_PEEKUSER, pid, sizeof (long) * P_XAX) }
# define get_xip(pid) { ptrace(PTRACE_PEEKUSER, pid, sizeof (long) * INSTR_REG) }
# define void_of(number) { reinterpret_cast<void*>(number) }
# define ANCHOR(x) fprintf(OUT, "\033[3%d;1mANCHOR #%d\033[0m\n", x % 7, x)

/* Thank you circular dependencies... */
class Tracker;
class Breaker
{
public:
        Breaker(std::string binary_name, pid_t pid);
        struct r_debug* get_r_debug(pid_t pid);
        void remove_breakpoint(std::string, void* addr);
        void add_breakpoint(std::string, void* addr);
        ssize_t find_syscalls(void* addr);
        char is_from_us(void* addr) const;
        long handle_bp(void* addr, bool print, Tracker& t);
        long handle_bp(void* addr, bool print);
	long exec_breakpoint(std::string region, void* addr, bool print);
        long exec_breakpoint(std::string region, void* addr, bool print, Tracker& t);
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

class Mapped
{
public:
        Mapped(unsigned long b, unsigned long len, unsigned long prot, int id_inc)
        {
                mapped_begin       = b;
                mapped_length      = len;
                mapped_protections = prot;
                id = id_inc;
        }

        bool area_contains(unsigned long addr) const;

        unsigned long mapped_begin;
        unsigned long  mapped_length;
        unsigned long  mapped_protections;
        int id; // For debug purposes
};


class Tracker
{
public:
        Tracker(std::string binary_name, pid_t child)
        {
                pid = child;
                name = binary_name;
                origin_program_break = 0;
                actual_program_break = 0;
                id_inc = 0;
        }


        bool of_interest(int syscall) const;
        void print_mapped_areas()     const;

        int handle_brk(Breaker& b, void* bp, bool print);
        int handle_munmap(Breaker& b, void* bp, bool print);
        int handle_mmap(Breaker& b, void* bp, bool print);
        int handle_syscall(int syscall, Breaker& b, void* bp, bool print);
        int handle_mprotect(Breaker& b, void* bp, bool print);
        int handle_mremap(Breaker& b, void* bp, bool print);
        int custom_alloc(int prefix, Breaker& b, void* bp, bool print);
        int custom_free(Breaker& b, void* bp, bool print);
        int custom_realloc(Breaker& b, void* bp, bool print);
        bool remove_mapped(void* addr, long len);
        std::list<Mapped>::iterator get_mapped(unsigned long addr);
        void tail_remove(std::list<Mapped>::iterator it, int iteration);

        std::list<Mapped> mapped_areas;
        std::string       name;
        pid_t             pid;
        void*           actual_program_break;
        void*           origin_program_break;
        int               id_inc;
};

#endif /* !DEFINES_HH */
