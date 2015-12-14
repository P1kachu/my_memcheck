#include "level3.hh"

static bool compare_address(Mapped first, Mapped second)
{
        char* first_addr = (char*)first.mapped_begin();
        char* second_addr = (char*)second.mapped_begin();
        return first_addr < second_addr;
}


bool Mapped::area_contains(void* addr) const
{
        return (char*)addr < (char*)mapped_begin_ + mapped_length_
                             && (char*)addr >= (char*)mapped_begin_;
}


bool Tracker::of_interest(int syscall) const
{
        return syscall == MMAP_SYSCALL || syscall == MREMAP_SYSCALL
                || syscall == MUNMAP_SYSCALL || syscall == MPROTECT_SYSCALL
                || syscall == BRK_SYSCALL;
}

int Tracker::handle_mmap(int syscall, Breaker& b, void* bp)
{
        print_syscall(pid, syscall);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        long retval = b.handle_bp(bp, false);
        print_retval(pid, syscall);

        if ((void*) retval == MAP_FAILED)
                return retval;

        if ((regs.r10 & MAP_SHARED) || !(regs.r10 & MAP_ANONYMOUS))
                return retval;

        unsigned i = 0;
        for (i = 0; i < regs.rsi / PAGE_SIZE; ++i)
                mapped_areas.push_back(Mapped(retval + i * 4096, 4096, regs.rdx));

        if (regs.rsi % 4096)
                mapped_areas.push_back(Mapped(retval + i * 4096, regs.rsi % 4096, regs.rdx));

        mapped_areas.sort(compare_address);

        return retval;
}

int Tracker::handle_syscall(int syscall, Breaker& b, void* bp)
{
        switch (syscall)
        {
                case MMAP_SYSCALL:
                        return handle_mmap(syscall, b, bp);
                default:
                        return b.handle_bp(bp, false);

        }

        return NO_SYSCALL;
}

void Tracker::print_mapped_areas() const
{
        int i = 0;
        for (auto it = mapped_areas.begin(); it != mapped_areas.end(); it++)
        {
                fprintf(OUT, "Mapped area #%d\n", i);
                fprintf(OUT, "\tBegins:\t%p\n", (void*)it->mapped_begin());
                fprintf(OUT, "\tLength:\t%ld\n", it->mapped_length());
                fprintf(OUT, "\tEnds  :\t%p\n", (char*)it->mapped_begin()
                        + it->mapped_length());
                fprintf(OUT, "\tProtections:\t%ld\n", it->mapped_protections());
                ++i;
        }

}
