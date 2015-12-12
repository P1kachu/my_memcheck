#include "level1.hh"
#include "level2.hh"

static int mem_hook(std::string name, pid_t pid)
{
  setenv("LD_BIND_NOW", "1", 1); //FIXME : Potential dead code
  int status = 0;
  waitpid(pid, &status, 0);
  Breaker b(name, pid);
  b.add_breakpoint(MAIN_CHILD, b.rr_brk);
  b.print_bps();
  b.remove_breakpoint(MAIN_CHILD, b.rr_brk);
  ptrace(PTRACE_CONT, pid, 0, 0);
  return 0;
}

int main(int argc, char** argv)
{
  if (argc < 2)
  {
    fprintf(OUT, "Usage: %s binary_to_trace [ARGS]\n", argv[0]);
    return 0;
  }

  std::string name = argv[1];

  if (!binary_exists(name) && name.find("./") != std::string::npos)
  {
    fprintf(OUT, "%sERROR:%s Binary %s not found.\n", RED, NONE, name.c_str());
    exit(-1);
  }

  pid_t pid = 0;

  if ((pid = fork()) != 0)
    return mem_hook(name, pid);

  return run_child(argc - 1, argv + 1);
}
