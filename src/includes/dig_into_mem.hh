#ifndef DIG_IN_HH
# define DIG_IN_HH

# include "defines.hh"

void* get_r_brk(void* rr_debug, pid_t pid_child);
void* get_pt_dynamic(unsigned long phent, unsigned long phnum,
                     pid_t pid_child, void* at_phdr);
void* get_final_r_debug(Elf64_Dyn* dt_struct, pid_t pid_child);
void* get_phdr(unsigned long& phent, unsigned long& phnum, pid_t pid_child);
void* get_link_map(void* rr_debug, pid_t pid, int* status);
void* print_string_from_mem(void* str, pid_t pid);
void browse_link_map(void* link_m, pid_t pid, Breaker* b);
int disass(const char* name, void* phdr, int len, Breaker b, pid_t pid);
std::pair<off_t, int>get_sections(const char* lib_name);
#endif /* !DIG_IN_HH */
