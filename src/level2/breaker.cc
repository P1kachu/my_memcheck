#include "level2.hh"

struct r_debug* Breaker::get_r_debug(pid_t pid_child)
{
        Elf64_Dyn* dt_struct = NULL;
        unsigned long at_phent = 0;
        unsigned long at_phnum = 0;


        // Get interesting Phdr
        void* at_phdr  = get_phdr(at_phent, at_phnum, pid_child);

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


        // FIXME : Deadcode
        //fprintf(OUT, "Found r_debug\t\t%p\n", rr_debug);
        //fprintf(OUT, "Found r_debug->r_brk\t%p\n", rr_brk);

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
        // FIXME : Deadcode
        // fprintf(OUT, "%sDELETED%s\n", RED, NONE);
}

void Breaker::add_breakpoint(std::string region, void* addr)
{
        // Get origin instruction and save it
        unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
        print_errno();

        // Address already patched
        if (handled_syscalls[region].find(addr) != handled_syscalls[region].end())
        {
                handled_syscalls[region].find(addr)->second = instr;
                // FIXME : Deadcode
                // fprintf(OUT, "%sUPDATED%s\n", RED, NONE);
        }
        else
        {
                handled_syscalls[region][addr] = instr;
                // FIXME : Deadcode
                // fprintf(OUT, "%sADDED%s\n", RED, NONE);
        }

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

long Breaker::handle_bp(void* addr, bool print)
{
        if (addr == rr_brk)
        {
                printf("(brk)\n");
                int state = 0;
                void* link_map = get_link_map(r_deb, pid, &state);
                printf("%s[%d]%s State: %s\n", GREEN, pid, NONE,
                       state ? state > 1
                       ? "DELETE"
                       : "ADD"
                       : "CONSISTENT");
                if (state == r_debug::RT_CONSISTENT)
                        browse_link_map(link_map, pid, this);
                if (state == r_debug::RT_DELETE)
                        reset_libs(link_map);
                return NO_SYSCALL;
        }
        else
                for (auto it : handled_syscalls)
                        if (it.second.find(addr) != it.second.end())
                                return exec_breakpoint(it.first, addr, print);

        return SYSCALL_ERROR;
}

long Breaker::exec_breakpoint(std::string region, void* addr, bool print)
{
        int wait_status = 0;

        // Not found
        auto it = handled_syscalls.find(region);
        if (it->second.find(addr) == it->second.end())
                return NO_SYSCALL;

        struct user_regs_struct regs;

        // Restore old instruction pointer
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        regs.XIP -= 1;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

        if (print)
                print_syscall(pid, regs.XAX);

        // Run instruction
        remove_breakpoint(region, addr);
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

        waitpid(pid, &wait_status, 0);

        if (print)
                print_retval(pid, regs.XAX);

        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        long retval = regs.XAX;

        if (WIFEXITED(wait_status))
                throw std::logic_error("EXITED");

        add_breakpoint(region, addr);

        return retval;
}

void Breaker::print_bps() const
{
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
                                fprintf(OUT, "\t\t%3d: %p (r_brk):\n", i, iter.first);
                        else
                                fprintf(OUT, "\t\t%3d: %p :\n", i, iter.first);

                        fprintf(OUT, "\t\t\t%8lx (origin)\n", iter.second);
                        fprintf(OUT, "\t\t\t%8lx (actual)\n", instr);
                        i++;
                }
                printf("\t}\n");
        }
        printf("}\n");
}

void Breaker::reset_libs(void* link_map)
{
        // Crappy version
        // Correct version would be to iterate through the libs
        // list and check the one that is NOT into the map
        // But fuck it, already short on time
        for (auto& region : handled_syscalls)
        {
                if (!strcmp(region.first.c_str(), MAIN_CHILD))
                    continue;
                handled_syscalls.erase(region.first);
        }
        browse_link_map(link_map, pid, this);
}
