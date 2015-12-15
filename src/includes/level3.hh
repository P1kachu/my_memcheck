#ifndef LEVEL3_HH
# define LEVEL3_HH

# include "defines.hh"
# include "level2.hh"
class Mapped
{
public:
        Mapped(long b, int len, long prot, int id_inc)
        {
                mapped_begin       = b;
                mapped_length      = len;
                mapped_protections = prot;
                id = id_inc;
        }

        bool area_contains(unsigned long addr) const;

        unsigned long mapped_begin;
        unsigned long  mapped_length;
        long  mapped_protections;
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

        int handle_brk(int syscall, Breaker& b, void* bp);
        int handle_munmap(int syscall, Breaker& b, void* bp);
        int handle_mmap(int syscall, Breaker& b, void* bp);
        int handle_syscall(int syscall, Breaker& b, void* bp);
        int handle_mprotect(int syscall, Breaker& b, void* bp);
        int handle_mremap(int syscall, Breaker& b, void* bp);

        bool remove_mapped(void* addr, long len);
        std::list<Mapped>::iterator get_mapped(unsigned long addr);
        void tail_remove(std::list<Mapped>::iterator it, int iteration);

        std::list<Mapped> mapped_areas;
        std::string       name;
        pid_t             pid;
        void*             actual_program_break;
        void*             origin_program_break;
        int               id_inc;
};


#endif /* LEVEL3_HH */
