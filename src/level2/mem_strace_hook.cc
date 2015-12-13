#include "level1.hh"

static unsigned long get_xip(pid_t pid)
{
        struct user_regs_struct regs;

        // Get child register and store them into regs
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        return regs.XIP;

}

static int mem_hook(std::string name, pid_t pid)
{
        setenv("LD_BIND_NOW", "1", 1); //FIXME : Potentialy bad
        int status = 0;
        waitpid(pid, &status, 0);

        Breaker b(name, pid);
        b.add_breakpoint(MAIN_CHILD, b.rr_brk);

        // FIXME : DEADCODE
        b.print_bps();

        while (1)
        {
                ptrace(PTRACE_CONT, pid, 0, 0);

                waitpid(pid, &status, 0);

                auto bp = reinterpret_cast<void*>(get_xip(pid) - 1);

                if (WIFEXITED(status))
                        break;
                if (WIFSIGNALED(status))
                        break;

                fprintf(OUT, "%s[%d]%s Signal received (%d): %p - %s%s%s\n",
                        GREEN, pid, NONE, status, (void*)bp, RED,
                        strsignal(WSTOPSIG(status)), NONE);

                if (status == 2943)
                        break;
                try
                {
                        if (b.is_from_us(bp))
                                b.handle_bp(bp);
                }
                catch (std::logic_error) { break; }
        }


        ptrace(PTRACE_CONT, pid, 0, 0);
        return 0;
}

int main(int argc, char** argv)
{
        if (argc < 2)
        {
                fprintf(OUT, "Usage: %s binary_to_trace[ARGS]\n", argv[0]);
                return 0;
        }

        std::string name = argv[1];

        if (!binary_exists(name) && name.find("./") != std::string::npos)
        {
                fprintf(OUT, "%sERROR:%s Binary %s not found.\n",
                        RED, NONE, name.c_str());
                exit(-1);
        }

        pid_t pid = 0;

        if ((pid = fork()) != 0)
                return mem_hook(name, pid);

        return run_child(argc - 1, argv + 1);
}
