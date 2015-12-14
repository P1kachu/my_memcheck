#include "level1.hh"
#include "level2.hh"

static int mem_hook(std::string name, pid_t pid)
{
        setenv("LD_BIND_NOW", "1", 1); //FIXME : Potentialy bad
        int status = 0;
        waitpid(pid, &status, 0);

        Breaker b(name, pid);
        b.add_breakpoint(MAIN_CHILD, b.rr_brk);

        while (1)
        {
                ptrace(PTRACE_CONT, pid, 0, 0);

                waitpid(pid, &status, 0);

                long addr = get_xip(pid);
                auto bp = (void*)(addr - 1);


                if (WIFEXITED(status))
                      break;
                if (WIFSIGNALED(status))
                      break;
#if 0
                fprintf(OUT, "%s[F %d]%s 0x%lx : %lx - Received %s%s%s\n",
                        GREEN, pid, NONE, get_xip(pid) - 1, ptrace(PTRACE_PEEKDATA, pid, get_xip(pid) - 1, 0),
                        RED, strsignal(WSTOPSIG(status)), NONE);
#endif
                if (status == 2943)
                        break;

                try
                {
                        if (b.is_from_us(bp))
                                b.handle_bp(bp, true);

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

        return run_child(argc - 1, argv + 1, NULL);
}
