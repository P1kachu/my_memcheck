#ifndef DIG_IN_HH
# define DIG_IN_HH

# include "defines.hh"

void* get_phdr(unsigned long& phent, unsigned long& phnum, pid_t pid_child);
void* get_link_map(void* rr_debug, pid_t pid);
void print_string_from_mem(void* str, pid_t pid);
void browse_link_map(void* link_map, pid_t pid);

#endif /* !DIG_IN_HH */
