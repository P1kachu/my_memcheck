#ifndef LEVEL3_HH
# define LEVEL3_HH

# include "defines.hh"

class Mapped
{
        Mapped();

        void* mapped_begin;
        void* mapped_end;
        long mapped_length;
        int protection;
}


class Tracker
{
public:
        Tracker(std::string binary_name, pid_t pid);
        bool of_interest(int syscall) const;


        std::string name;
        pid_t pid;
};


#endif /* LEVEL3_HH */
