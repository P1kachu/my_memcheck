#include "level1.hh"
#include "syscalls.hh"

static int wait_for_syscall(pid_t child)
{
        int status = 0;
        while (true)
        {
                // Trace system calls from child
                if (ptrace(PTRACE_SYSCALL, child, 0, 0) == -1)
                        fprintf(OUT,
                                "%sERROR:%s PTRACE_SYSCALL failed\n",
                                RED, NONE);

                //       pid, status, options
                waitpid(child, &status, __WALL);

                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
			return fprintf(OUT, "[%d] Signal 11 caught (SIGSEGV)\n", child);



                // Program was stopped by a syscall
                if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
                        return 0;

                // Program exited normally
                if (WIFEXITED(status))
                        return 1;
        }
}


int run_child(int argc, char** argv, char* ld_preload)
{
        char** args = new char* [argc + 1];
        memcpy(args, argv, argc * sizeof (char*));
        args[argc] = nullptr; // TODO : Ask ACU if this is clean

        if (ptrace(PTRACE_TRACEME) == -1)
                fprintf(OUT,
                        "%sERROR:%s PTRACE_TRACEME failed\n",
                        RED, NONE);

        int ret = 0;
        if (ld_preload)
        {
                std::stringstream ss;
                ss << "LD_PRELOAD=" << ld_preload;
                std::string s = ss.str();

                char* tmp = strdup(s.c_str());
                char* const envs[] = { tmp, NULL };
                ret = execve(args[2], args + 2, envs);

                free(tmp);
                delete[] args;
        }
        else
        {
                ret = execvp(args[0], args);
                delete[] args;
        }
        return ret;
}


int trace_child(pid_t child)
{
        int status = 0;
        int retval = 0;
        waitpid(child, &status, 0);

        // PTRACE_O_TRACESYSGOOD is used to
        // differentiate syscalls from normal traps
        if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD))
                fprintf(OUT,
                        "%sERROR:%s PTRACE_O_TRACESYSGOOD failed\n",
                        RED, NONE);

        while (true)
        {

                if (wait_for_syscall(child))
                        break;


                // Retrieve data from $rax
                long syscall = get_orig_xax(child);

                int rdi = print_syscall(child, syscall);

                int tmp = wait_for_syscall(child);

                retval = print_retval(child, syscall);

                if (syscall == EXIT_SYSCALL || syscall == EXIT_GROUP_SYSCALL)
                        retval = rdi;

                if (tmp)
                        break;

        }

        fprintf(OUT, "\n+++ Process %d exited with %d+++\n", child, retval);
        return 0;

}
