#ifndef LEVEL3_HH
# define LEVEL3_HH

# include "defines.hh"

class Mapped
{
public:
        Mapped(void* b, int len, int prot)
        {
                mapped_begin_       = b;
                mapped_length_      = len;
                mapped_protections_ = prot;
        }

        bool  area_contains(void* addr) const;
        void* mapped_begin()            const { return mapped_begin_; }
        long  mapped_length()           const { return mapped_length_; }
        int   mapped_protections()      const { return mapped_protections_; }

        bool compare_address (Mapped first, Mapped second);

private:
        void* mapped_begin_;
        long  mapped_length_;
        int   mapped_protections_;
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

        int handle_mmap(int syscall);
        int handle_syscall(int syscall);


        std::list<Mapped> mapped_areas;
        std::string       name;
        pid_t             pid;
};


#endif /* LEVEL3_HH */
