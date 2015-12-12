#ifndef LEVEL2_HH
# define LEVEL2_HH

# include "dig_into_mem.hh"

class Breaker
{
public:
        Breaker(std::string binary_name, pid_t pid);
        struct r_debug* get_r_debug(pid_t pid);
        void remove_breakpoint(const char* region, void* addr);
        void add_breakpoint(const char* region, void* addr);
        ssize_t find_syscalls(void* addr);
        char is_from_us(void* addr) const;
        void handle_bp(void* addr);
        void exec_breakpoint(const char* region, void* addr);
        int parse_elf(char* elf_name);
        void print_bps() const;


        // Vars
        std::map<const char*, std::map<void*, unsigned long>> handled_syscalls;
        void* rr_brk;
        pid_t pid;
        struct r_debug* r_deb;
        std::string name;
};

#endif /* LEVEL2_HH */
