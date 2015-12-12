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

void Breaker::remove_breakpoint(const char* region, void* addr)
{
        UNUSED(region);
        /*
          auto it = handled_syscalls.find(region);

          printf("##%s##\n", it->first);

          if (it == handled_syscalls.end())
          {
          fprintf(OUT,
          "%sERROR:%s Region %s not found in map (remove)\n",
          RED, NONE, region);
          return;
          }

          auto breaks = it->second;
        */
        auto& breaks = handled_syscalls;

        // No breakpoint found at this address
        if (breaks.find(addr) == breaks.end())
                return;

        // Get saved instruction and rewrite it in memory
        ptrace(PTRACE_POKEDATA, pid, addr, breaks.find(addr)->second);

        breaks.erase(addr);
}

void Breaker::add_breakpoint(const char* region, void* addr)
{
        // Get origin instruction and save it
        unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
        UNUSED(region);
        print_errno();

        /*
          auto it = handled_syscalls.find(region);

          if (it == handled_syscalls.end())
          {
          std::map<void*, unsigned long>* inner =
          new std::map<void*, unsigned long>;
          inner->insert(std::make_pair(addr, instr));
          handled_syscalls.insert(std::pair<const char*,
          std::map<void*,
          unsigned long>>(region, * inner));
          return;
          }

          //auto breaks = it->second;

          if (breaks.find(addr) != breaks.end())
          return; // Address already patched

          breaks.insert(std::pair<void*, unsigned long>(addr, instr));
        */

        // Replace it with an int3 (CC) opcode sequence

        // Address already patched
        if (handled_syscalls.find(addr) != handled_syscalls.end())
                return;


        handled_syscalls.insert(std::pair<void*, unsigned long>(addr, instr));


        ptrace(PTRACE_POKETEXT, pid, addr, (instr & TRAP_MASK) | TRAP_INST);
}

char Breaker::is_from_us(void* addr) const
{
        return handled_syscalls.find(addr) != handled_syscalls.end();
}

void Breaker::handle_bp(void* addr)
{
        printf("%s[%d]%s %%rip = %p ", GREEN, pid, NONE, addr);
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
                        browse_link_map(link_map, pid);

        }
        exec_breakpoint(addr);
}

void Breaker::exec_breakpoint(void* addr)
{
        // Not found
        if (handled_syscalls.find(addr) == handled_syscalls.end())
                return;

        struct user_regs_struct regs;

        // Restore old instruction pointer
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        regs.XIP -= 1;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

        // Run instruction
        remove_breakpoint(NULL, addr);
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

        int wait_status = 0;
        waitpid(pid, &wait_status, 0);
        if (WIFEXITED(wait_status))
                throw std::logic_error("EXITED");

        add_breakpoint(NULL, addr);
}

void Breaker::print_bps() const
{
        int i = 0;
        /*
          for (auto& region : handled_syscalls)
          {
          fprintf(OUT, "%s: ", region.first);
          for (auto& iter : region.second)
          {

        */
        for (auto& iter : handled_syscalls)
        {
                unsigned long instr =
                        ptrace(PTRACE_PEEKDATA, pid, iter.first, 0);
                if (iter.first == rr_brk)
                        fprintf(OUT, "%3d: %p (r_brk):\n", i, iter.first);
                else
                        fprintf(OUT, "%3d: %p :\n", i, iter.first);

                fprintf(OUT, "\t%8lx (origin)\n", iter.second);
                fprintf(OUT, "\t%8lx (actual)\n", instr);
        }
}
