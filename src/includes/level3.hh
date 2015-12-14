#ifndef LEVEL3_HH
# define LEVEL3_HH

# include "defines.hh"
# include "level2.hh"
class Mapped
{
public:
        Mapped(long b, int len, long prot)
        {
                mapped_begin_       = b;
                mapped_length_      = len;
                mapped_protections_ = prot;
        }

        bool  area_contains(void* addr) const;
        long  mapped_begin()            const { return mapped_begin_; }
        long  mapped_length()           const { return mapped_length_; }
        long  mapped_protections()      const { return mapped_protections_; }

private:
        long mapped_begin_;
        long  mapped_length_;
        long  mapped_protections_;
};


class Tracker
{
public:
        Tracker(std::string binary_name, pid_t child)
        {
                pid = child;
                name = binary_name;
        }


        bool of_interest(int syscall) const;
        void print_mapped_areas()     const;

        int handle_munmap(int syscall, Breaker& b, void* bp);
        int handle_mmap(int syscall, Breaker& b, void* bp);
        int handle_syscall(int syscall, Breaker& b, void* bp);

        bool remove_mapped(void* addr, long len);
        std::list<Mapped>::iterator get_mapped(void* addr);
        void tail_remove(std::list<Mapped>::iterator it, int iteration);

        std::list<Mapped> mapped_areas;
        std::string       name;
        pid_t             pid;
};


#endif /* LEVEL3_HH */
