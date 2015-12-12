#ifndef DIG_IN_HH
# define DIG_IN_HH

# include "defines.hh"

void* get_phdr(unsigned long& phent, unsigned long& phnum, pid_t pid_child);

#endif /* !DIG_IN_HH */
