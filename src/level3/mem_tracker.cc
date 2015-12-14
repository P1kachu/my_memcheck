#include "level1.hh"
#include "level2.hh"
#include "level3.hh"

static unsigned long get_xip(pid_t pid)
{
        struct user_regs_struct regs;

        // Get child register and store them into regs
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        return regs.XIP;

}

static int mem_tracker(std::string name, pid_t pid)
{
        setenv("LD_BIND_NOW", "1", 1); //FIXME : Potentialy bad
        int status = 0;
        waitpid(pid, &status, 0);

        Breaker b(name, pid);
        Tracker t(name, pid);

        b.add_breakpoint(MAIN_CHILD, b.rr_brk);

        while (1)
        {
                ptrace(PTRACE_CONT, pid, 0, 0);

                waitpid(pid, &status, 0);

                auto bp = (void*)(get_xip(pid) - 1);

                if (WIFEXITED(status))
                      break;
                if (WIFSIGNALED(status))
                      break;

                // Segfault
                if (status == 2943)
                        break;
                try
                {
                        if (!b.is_from_us(bp))
                                continue;

                        int syscall = b.handle_bp(bp, false);

                        if (!t.of_interest(syscall))
                                continue;

                        t.handle_syscall(syscall);

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
                fprintf(OUT, "Usage: %s [--preload lib] binary_to_trace[ARGS]\n", argv[0]);
                return 0;
        }

        std::string name = argv[1];

        char* preload = get_cmd_opt(argv, argv + argc, "--preload");
        if (preload)
        {
                name = argv[3];
                printf("Preloaded: %s\n", preload);
                printf("Binary: %s\n", name.c_str());
        }
        else
        {
                if (!binary_exists(name) && name.find("--") != std::string::npos)
                {
                        fprintf(OUT, "%sERROR:%s Invalid command option (%s)\n",
                                RED, NONE, name.c_str());
                        exit(-1);
                }
        }

        if (!binary_exists(name) && name.find("./") != std::string::npos)
        {
                fprintf(OUT, "%sERROR:%s Binary %s not found.\n",
                        RED, NONE, name.c_str());
                exit(-1);
        }




        pid_t pid = 0;

        if ((pid = fork()) != 0)
                return mem_tracker(name, pid);

        return run_child(argc - 1, argv + 1);

}
