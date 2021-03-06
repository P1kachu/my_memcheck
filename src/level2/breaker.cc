#include "level4.hh"

struct r_debug* Breaker::get_r_debug(pid_t pid_child)
{
        Elf64_Dyn* dt_struct = NULL;
        unsigned long at_phent = 0;
        unsigned long at_phnum = 0;


        // Get interesting Phdr
        void* at_phdr  = get_phdr(at_phent, at_phnum, pid_child);

        print_errno();

        // Something went wrong ?
        if (!at_phdr)
                return NULL;


        // FIXME : Check if ELF ? Get Ehdr, helpers/is_elf

        // Get PT_DYNAMIC entry
        dt_struct = (Elf64_Dyn*)get_pt_dynamic(at_phent, at_phnum,
                                               pid_child, at_phdr);


        // Get r_debug address
        void* rr_debug = get_final_r_debug(dt_struct, pid_child);


        // Get r_debug content
        rr_brk = get_r_brk(rr_debug, pid_child);

	// Return r_debug struct address
        return reinterpret_cast<struct r_debug*>(rr_debug);
}

Breaker::Breaker(std::string binary_name, pid_t p)
{
        pid = p;
        r_deb = get_r_debug(pid);
        name = binary_name;
        if (!r_deb)
        {
                fprintf(OUT, "%sERROR:%s Recovering r_debug struct failed\n",
                        RED, NONE);
                throw std::logic_error("r_debug not found");
        }
}

void Breaker::remove_breakpoint(std::string region, void* addr)
{
        auto it = handled_syscalls.find(region);

        if (it == handled_syscalls.end())
        {
                fprintf(OUT,
                        "%sERROR:%s Region %s not found in map (remove)\n",
                        RED, NONE, region.c_str());
                return;
        }

        auto breaks = it->second;

        // No breakpoint found at this address
        if (breaks.find(addr) == breaks.end())
                return;

        // Get saved instruction and rewrite it in memory
        ptrace(PTRACE_POKEDATA, pid, addr, breaks.find(addr)->second);
        handled_syscalls[region].erase(addr);
}

void Breaker::add_breakpoint(std::string r, void* addr)
{
        // Get origin instruction and save it
        unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);

        // Address already patched
	// r stands for region
        if (handled_syscalls[r].find(addr) != handled_syscalls[r].end())
                handled_syscalls[r].find(addr)->second = instr;
        else
                handled_syscalls[r][addr] = instr;

        // Replace it with an int3 (CC) opcode sequence
        ptrace(PTRACE_POKEDATA, pid, addr, (instr & TRAP_MASK) | TRAP_INST);
}

char Breaker::is_from_us(void* addr) const
{
        for (auto& it : handled_syscalls)
                if (it.second.find(addr) != it.second.end())
                        return 1;
        return 0;
}

long Breaker::handle_bp(void* addr, bool p, Tracker& t)
{
        if (addr == rr_brk)
        {
                int state = 0;
                void* link_map = get_link_map(r_deb, pid, &state);

                if (state == r_debug::RT_CONSISTENT)
                        browse_link_map(link_map, pid, this);

                return NO_SYSCALL;
        }
        else
                for (auto it : handled_syscalls)
                        if (it.second.find(addr) != it.second.end())
				// p stands for 'print'
                                return exec_breakpoint(it.first, addr, p, t);

        return SYSCALL_ERROR;
}

long Breaker::handle_bp(void* addr, bool print)
{
        if (addr == rr_brk)
        {
                int state = 0;
                void* link_map = get_link_map(r_deb, pid, &state);

                if (state == r_debug::RT_CONSISTENT)
                        browse_link_map(link_map, pid, this);

                return NO_SYSCALL;
        }
        else
                for (auto it : handled_syscalls)
                        if (it.second.find(addr) != it.second.end())
                                return exec_breakpoint(it.first, addr, print);

        return SYSCALL_ERROR;

}

long Breaker::exec_breakpoint(std::string r, void* addr, bool p, Tracker& t)
{
        int wait_status = 0;

        // Not found
        auto it = handled_syscalls.find(r);
        if (it->second.find(addr) == it->second.end())
                return NO_SYSCALL;

        struct user_regs_struct regs;
        if ((it->second.find(addr)->second & 0xFF) == TRAP_INST)
        {
		sanity_customs(pid, t, 0);
                ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
                waitpid(pid, 0, 0);

                return CUSTOM_BREAKPOINT;
        }

        // Restore old instruction pointer
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        regs.XIP -= 1;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

        p ? print_syscall(pid, regs.XAX) : p = p;

        // Run instruction
        remove_breakpoint(r, addr);

        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

        waitpid(pid, &wait_status, 0);
        sanity_customs(pid, t, 0);

        p ? print_retval(pid, regs.XAX) : p = p;

        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        long retval = regs.XAX;
        if (WIFEXITED(wait_status))
                throw std::logic_error("EXITED");
        add_breakpoint(r, addr);

        return retval;

}
long Breaker::exec_breakpoint(std::string region, void* addr, bool print)
{
        int wait_status = 0;

        // Not found
        auto it = handled_syscalls.find(region);
        if (it->second.find(addr) == it->second.end())
                return NO_SYSCALL;

        struct user_regs_struct regs;

        if ((it->second.find(addr)->second & 0xFF) == TRAP_INST)
        {
                ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
                waitpid(pid, 0, 0);
                return CUSTOM_BREAKPOINT;
        }

        // Restore old instruction pointer
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        regs.XIP -= 1;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

        print ? print_syscall(pid, regs.XAX) : print = print;

        // Run instruction
        remove_breakpoint(region, addr);
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

        waitpid(pid, &wait_status, 0);

        print ? print_retval(pid, regs.XAX) : print = print;

        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        long retval = regs.XAX;
        if (WIFEXITED(wait_status))
                throw std::logic_error("EXITED");
        add_breakpoint(region, addr);

        return retval;
}

void Breaker::print_bps() const
{
	/*
	** For debugging purposes
	*/
        printf("Number of zones: %ld\n{\n", handled_syscalls.size());
        for (auto& region : handled_syscalls)
        {
                printf("\tNumber of breakpoints in %s: %s%ld%s\n\t{\n",
                       region.first.c_str(), BLUE, region.second.size(), NONE);
                int i = 0;
                for (auto& iter : region.second)
                {
                        unsigned long instr =
                                ptrace(PTRACE_PEEKDATA, pid, iter.first, 0);
                        if (iter.first == rr_brk)
                                fprintf(OUT, "\t\t%3d: %p (r_brk):\n", i,
                                        iter.first);
                        else
                                fprintf(OUT, "\t\t%3d: %p :\n", i, iter.first);

                        fprintf(OUT, "\t\t\t%8lx (origin)\n", iter.second);
                        fprintf(OUT, "\t\t\t%8lx (actual)\n", instr);
                        i++;
                }
                printf("\t}\n");
        }
        printf("}\n");
        printf("Exiting\n");
        exit(0); // For debug purposes
}

void Breaker::reset_libs(void* link_map)
{
	/*
	** Crappy version
	**
        ** Correct version would be to iterate through the libs
        ** list and check the one that is NOT into the map
        ** But fuck it, already short on time
	**/

        for (auto& region : handled_syscalls)
        {
                if (!strcmp(region.first.c_str(), MAIN_CHILD))
                    continue;
                handled_syscalls.erase(region.first);
        }
        browse_link_map(link_map, pid, this);
}
