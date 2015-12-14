#ifndef LEVEL1_HH
# define LEVEL1_HH

# include "defines.hh"

int run_child(int argc, char** argv, char* ld_preload);
int trace_child(pid_t child);

#endif /* LEVEL1_HH */
