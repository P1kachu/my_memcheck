#ifndef LEVEL4_HH
# define LEVEL4_HH

# include "level3.hh"

int remove_page_protection(void* addr, size_t len, pid_t pid);

#endif /* LEVEL4_HH */
