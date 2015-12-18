#include "level4.hh"

static bool compare_address(Mapped first, Mapped second)
{
        char* first_addr = (char*)first.mapped_begin;
        char* second_addr = (char*)second.mapped_begin;
        return first_addr < second_addr;
}

bool Mapped::area_contains(unsigned long addr) const
{
        int ret = (addr < mapped_begin + mapped_length)
		&& addr >= mapped_begin;
	if (0) // TODO : REMOVE
		printf("%s%12lx - %12lx - %12lx%s\n",
		       ret ? GREEN : RED, mapped_begin, addr,
		       mapped_begin + mapped_length, NONE);

        return ret;
}


bool Tracker::of_interest(int syscall) const
{
        return syscall == MMAP_SYSCALL
                || syscall == MREMAP_SYSCALL
                || syscall == MUNMAP_SYSCALL
                || syscall == MPROTECT_SYSCALL
                || syscall == BRK_SYSCALL
                || syscall == CUSTOM_SYSCALL_MALLOC
                || syscall == CUSTOM_SYSCALL_CALLOC
                || syscall == CUSTOM_SYSCALL_REALLOC
                || syscall == CUSTOM_SYSCALL_FREE;
}

std::list<Mapped>::iterator Tracker::get_mapped(unsigned long addr)
{
        for (auto it = mapped_areas.begin(); it != mapped_areas.end(); it++)
                if (it->area_contains(addr))
                        return it;
        return mapped_areas.end();
}


int Tracker::handle_mprotect(Breaker& b, void* bp, bool print)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

#if LEVEL == 4
        auto retval = b.handle_bp(bp, false, *this);
#else
	auto retval = b.handle_bp(bp, false);
#endif


        if (retval < 0)
                return retval;

        auto it = get_mapped(regs.rdi);
        if (it == mapped_areas.end())
                return NOT_FOUND;

	if (print)
		lvl3_print_mprotect(0, regs.rdi, regs.rsi, it->mapped_protections);

        long tmp = reinterpret_cast<long>(bp) - it->mapped_begin;
        regs.rsi -= tmp;

        if (regs.rsi > 0)
                regs.rsi = 0;

        it->mapped_protections = regs.rdx;
        for (unsigned i = 0; i < regs.rsi / PAGE_SIZE; ++i)
        {
                it = std::next(it);
                it->mapped_protections = regs.rdx;
        }

	if (print)
		lvl3_print_mprotect(1, regs.rdi, regs.rsi, it->mapped_protections);

        return retval;
}


void Tracker::tail_remove(std::list<Mapped>::iterator it, int iteration)
{
        if (iteration > 0 && (std::next(it) != mapped_areas.end()))
                tail_remove(std::next(it), iteration - 1);

        mapped_areas.erase(it);
        return;
}


int Tracker::handle_mremap(Breaker& b, void* bp, bool print)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

#if LEVEL == 4
        auto retval = b.handle_bp(bp, false, *this);
#else
	auto retval = b.handle_bp(bp, false);
#endif

        if ((void*) retval == MAP_FAILED)
                return retval;

        auto it = get_mapped(regs.rdi);
        if (it == mapped_areas.end())
                return NOT_FOUND;

	if (print)
		lvl3_print_mremap(0, regs.rdi, regs.rsi, it->mapped_protections);

        if ((unsigned long)retval != it->mapped_begin)
        {
                it->mapped_begin = retval;
                it->mapped_length = regs.rdx;
                tail_remove(it, regs.rsi / regs.rdx);
        }

        // Old size == New size
        else if (regs.rsi == regs.rdx)
                return retval;

        // Old size > New size <==> Shrinking
        else if (regs.rsi > regs.rdx)
        {
                it->mapped_length = regs.rdx;
                auto tmp = regs.rsi /  regs.rdx;
                tail_remove(std::next(it), tmp - 1);
        }
        // Expand
        else
        {
                unsigned i;
                for (i = 0; i < regs.rdx / PAGE_SIZE; ++i)
                {
                        long addr = retval + i * PAGE_SIZE;
                        mapped_areas.push_back(Mapped(addr, PAGE_SIZE,
                                                      it->mapped_protections,
						      id_inc++));
                }

                if (regs.rdx % PAGE_SIZE)
                {
                        long addr = retval + i * PAGE_SIZE;
                        long len = regs.rdx % PAGE_SIZE;
                        mapped_areas.push_back(Mapped(addr, len,
                                                      it->mapped_protections,
						      id_inc++));
                }
                mapped_areas.erase(it);

        }
	if (print)
		lvl3_print_mremap(1, retval, regs.rdx, it->mapped_protections);
        mapped_areas.sort(compare_address);
        return retval;
}

int Tracker::handle_mmap(Breaker& b, void* bp, bool print)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

#if LEVEL == 4
        auto retval = b.handle_bp(bp, false, *this);
#else
	auto retval = b.handle_bp(bp, false);
#endif
        if ((void*) retval == MAP_FAILED)
                return retval;

        if ((regs.r10 & MAP_SHARED) || !(regs.r10 & MAP_ANONYMOUS))
                return retval;

        unsigned i = 0;
        for (i = 0; i < regs.rsi / PAGE_SIZE; ++i)
        {
                long addr = retval + i * PAGE_SIZE;
                mapped_areas.push_back(Mapped(addr, PAGE_SIZE,
					      regs.rdx, id_inc++));
        }

        if (regs.rsi % PAGE_SIZE)
        {
                long addr = retval + i * PAGE_SIZE;
                long len = regs.rsi % PAGE_SIZE;
                mapped_areas.push_back(Mapped(addr, len,
					      regs.rdx, id_inc++));
        }
	if (print)
		fprintf(OUT,
			"mmap     { addr = 0x%lx, len = 0x%llx, prot = %lld } \n",
			retval, regs.rsi, regs.rdx);

        mapped_areas.sort(compare_address);

#if LEVEL == 4
	set_page_protection(retval, regs.rsi, PROT_EXEC, pid);
#endif
        return retval;
}

int Tracker::handle_brk(Breaker& b, void* bp, bool print)
{
        static int origin_set = 0;
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	if (print)
		lvl3_print_brk(0, origin_program_break, actual_program_break);



#if LEVEL == 4
        long retval = b.handle_bp(bp, false, *this);
#else
	long retval = b.handle_bp(bp, false);
#endif

        if (retval < 0)
                return 0;

        if (!origin_set)
        {
                origin_set = 1;
                origin_program_break = (void*)retval;
                actual_program_break = (void*)retval;
        }
        else
                actual_program_break = (void*)retval;

	if (print)
		lvl3_print_brk(1, origin_program_break, actual_program_break);

        return 0;

}

int Tracker::handle_munmap(Breaker& b, void* bp, bool print)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

#if LEVEL == 4
        long retval = b.handle_bp(bp, false, *this);
#else
	long retval = b.handle_bp(bp, false);
#endif

        if (retval < 0)
                return retval;

        auto it = get_mapped(regs.rdi);
        if (it == mapped_areas.end())
                return NOT_FOUND;

        unsigned long long addr = regs.rdi;
        unsigned long long len = regs.rsi;

	if (len < it->mapped_length)
	{
		mapped_areas.push_back(Mapped(addr + len,
					      it->mapped_length - len,
					      it->mapped_protections, id_inc++));
	}

	tail_remove(it, len / PAGE_SIZE);
	if (print)
		fprintf(OUT, "munmap   { addr = 0x%llx, len = 0x%llx } \n",
                addr, len);
        mapped_areas.sort(compare_address);
        return retval;
}

int Tracker::custom_alloc(int prefix, Breaker& b, void* bp, bool print)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

#if LEVEL == 4
        auto retval = b.handle_bp(bp, false, *this);
#else
	auto retval = b.handle_bp(bp, false);
#endif

        auto rbx = regs.rbx;
        auto rcx = regs.rcx;

        if (retval != CUSTOM_BREAKPOINT)
                return retval;

        mapped_areas.push_back(Mapped(rbx, rcx, MALLOC_CHILD, id_inc++));

	if (print)
	{
		if (!prefix)
			fprintf(OUT, "malloc   { addr = 0x%llx, len = 0x%llx } \n",
				rbx, rcx);
		else
			fprintf(OUT, "calloc   { addr = 0x%llx, len = 0x%llx } \n",
				rbx, rcx);
	}

#if LEVEL == 4
	set_page_protection(rbx, regs.rcx, PROT_EXEC, pid);
#endif


	mapped_areas.sort(compare_address);
        return retval;
}

int Tracker::custom_free(Breaker& b, void* bp, bool print)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

#if LEVEL == 4
        b.handle_bp(bp, false, *this);
#else
	b.handle_bp(bp, false);
#endif

        auto rbx = regs.rbx;
        auto it = get_mapped(rbx);

	if (it == mapped_areas.end())
		return -1;

        if (it == mapped_areas.end() || it->mapped_protections != MALLOC_CHILD)
        {
                // TODO : Invalid free
                return -1;
        }

	if (print)
		fprintf(OUT, "free     { addr = 0x%llx, len = 0x%lx } \n",
			rbx, it->mapped_length);

        mapped_areas.erase(it);

        return 0;
}


int Tracker::custom_realloc(Breaker& b, void* bp, bool print)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);


#if LEVEL == 4
        b.handle_bp(bp, false, *this);
#else
	b.handle_bp(bp, false);
#endif

	auto rbx = regs.rbx;
        auto rcx = regs.rcx;
        auto rdx = regs.rdx;

        auto it = get_mapped(rdx);

	if (it == mapped_areas.end())
		return -1;

	if (print)
	{
		lvl3_print_realloc(0, rdx, rbx, it->mapped_length);
		lvl3_print_realloc(1, rdx, rbx, rcx);
	}
        if (rbx != rcx)
        {
                mapped_areas.erase(it);
                mapped_areas.push_back(Mapped(rbx, rcx, MALLOC_CHILD, id_inc++));
        }
        else
                it->mapped_length = rcx;

        mapped_areas.sort(compare_address);
        return 0;
}


int Tracker::handle_syscall(int syscall, Breaker& b, void* bp, bool print)
{
        switch (syscall)
        {
                case MMAP_SYSCALL:
                        return handle_mmap(b, bp, print);
                case MUNMAP_SYSCALL:
                        return handle_munmap(b, bp, print);
                case MPROTECT_SYSCALL:
                        return handle_mprotect(b, bp, print);
                case MREMAP_SYSCALL:
                        return handle_mremap(b, bp, print);
                case BRK_SYSCALL:
                        return handle_brk(b, bp, print);
                case CUSTOM_SYSCALL_MALLOC:
                        return custom_alloc(0, b, bp, print);
                case CUSTOM_SYSCALL_CALLOC:
                        return custom_alloc(1, b, bp, print);
                case CUSTOM_SYSCALL_REALLOC:
                        return custom_realloc(b, bp, print);
                case CUSTOM_SYSCALL_FREE:
                        return custom_free(b, bp, print);
        }
        return b.handle_bp(bp, false);
}

void Tracker::print_mapped_areas() const
{
        printf("Origin process break %p\n", origin_program_break);
        printf("Actual process break %p\n", actual_program_break);
        for (auto it = mapped_areas.begin(); it != mapped_areas.end(); it++)
        {
                fprintf(OUT, "Mapped area #%d\n", it->id);
                fprintf(OUT, "\tBegins:\t%p\n", (void*)it->mapped_begin);
                fprintf(OUT, "\tLength:\t%ld\n", it->mapped_length);
                fprintf(OUT, "\tEnds  :\t%p\n", (char*)it->mapped_begin
                        + it->mapped_length);
                fprintf(OUT, "\tProt  :\t%lx\n\n", it->mapped_protections);
        }
}
