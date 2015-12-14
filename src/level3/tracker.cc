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



// ###############################################


bool Tracker::of_interest(int syscall) const
{
        return syscall == MMAP_SYSCALL || syscall == MREMAP_SYSCALL
                || syscall == MUNMAP_SYSCALL || syscall == MPROTECT_SYSCALL
                || syscall == BRK_SYSCALL;
}

std::list<Mapped>::iterator Tracker::get_mapped(void* addr)
{
        for (auto it = mapped_areas.begin(); it != mapped_areas.end(); it++)
                if(it->area_contains(addr))
                        return it;
        return mapped_areas.end();
}

void Tracker::tail_remove(std::list<Mapped>::iterator it, int iteration)
{
        if (iteration == 0 || std::next(it) != mapped_areas.end())
                return;

        tail_remove(std::next(it), iteration - 1);
        mapped_areas.erase(it);
}

bool Tracker::remove_mapped(void* addr, long len)
{
        auto it = get_mapped(addr);
        if (it != mapped_areas.end())
                return false;

        long tmp = reinterpret_cast<long>(addr) - it->mapped_begin();
        len -= tmp;

        if (len >0)
                len = 0;
        tail_remove(std::next(it), len / PAGE_SIZE);

        return true;
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
        {
                long addr = retval + i * PAGE_SIZE;
                mapped_areas.push_back(Mapped(addr, PAGE_SIZE, regs.rdx));
        }

        if (regs.rsi % PAGE_SIZE)
        {
                long addr = retval + i * PAGE_SIZE;
                long len = regs.rsi % PAGE_SIZE;
                mapped_areas.push_back(Mapped(addr, len, regs.rdx));
        }

        mapped_areas.sort(compare_address);

        return retval;
}

int Tracker::handle_brk(int syscall, Breaker& b, void* bp)
{
        static int origin_set = 0;

        print_syscall(pid, syscall);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        long retval = b.handle_bp(bp, false);
        print_retval(pid, syscall);
        if (retval < 0)
                return 0;

        if (!origin_set)
        {
                origin_set = 1;
                origin_program_break = (void*)retval;
        }
        else
                actual_program_break = (void*)retval;

        return 0;

}
int Tracker::handle_munmap(int syscall, Breaker& b, void* bp)
{
        print_syscall(pid, syscall);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        long retval = b.handle_bp(bp, false);
        print_retval(pid, syscall);

        if (retval < 0)
                return retval;

        if ((regs.r10 & MAP_SHARED) || !(regs.r10 & MAP_ANONYMOUS))
                return retval;

        remove_mapped(reinterpret_cast<void*>(retval), regs.rsi);

        mapped_areas.sort(compare_address);
        return retval;
}

int Tracker::handle_syscall(int syscall, Breaker& b, void* bp)
{
        switch (syscall)
        {
                case MMAP_SYSCALL:
                        return handle_mmap(syscall, b, bp);
                case MUNMAP_SYSCALL:
                        return handle_munmap(syscall, b, bp);
                case BRK_SYSCALL:
                        return handle_brk(syscall, b, bp);
                default:
                        return b.handle_bp(bp, false);

        }

        return NO_SYSCALL;
}

void Tracker::print_mapped_areas() const
{
        int i = 0;
        printf("Old process break %p\n", origin_program_break);
        printf("Actual process break %p\n", actual_program_break);
        for (auto it = mapped_areas.begin(); it != mapped_areas.end(); it++)
        {
                fprintf(OUT, "Mapped area #%d\n", i);
                fprintf(OUT, "\tBegins:\t%p\n", (void*)it->mapped_begin());
                fprintf(OUT, "\tLength:\t%ld\n", it->mapped_length());
                fprintf(OUT, "\tEnds  :\t%p\n", (char*)it->mapped_begin()
                        + it->mapped_length());
                fprintf(OUT, "\tProt  :\t%ld\n\n", it->mapped_protections());
                ++i;
        }
}
