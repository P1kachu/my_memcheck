#include "level1.hh"

// FIXME: Bonus maybe ?
typedef struct threading
{
        int argc;
        char **argv;
        pid_t pid;
} s_threading;

int main(int argc, char** argv)
{
        if (argc < 2)
        {
                fprintf(OUT,
                        "Usage: %s binary_to_trace[ARGS]\n",
                        argv[0]);
                return 0;
        }

        std::string name = argv[1];

        if (!binary_exists(name) && name.find("./") != std::string::npos)
        {
                // Binary not present
                fprintf(OUT,
                        "%sERROR:%s Binary %s not found.\n",
                        RED, NONE, name.c_str());
                exit(-1);
        }

        pid_t pid = 0;

        if ((pid = fork()) == 0)
                return run_child(argc - 1, argv + 1, NULL);

        return trace_child(pid);
}
