#ifndef LEVEL2_HH
# define LEVEL2_HH

# include "defines.hh"

// Recover r_brk address
void* get_r_brk(void* rr_debug, pid_t pid_child);

// Get pt_dynamic region to get r_debug
void* get_pt_dynamic(unsigned long phent, unsigned long phnum, pid_t pid, void* at_phdr);

// Wrapper to get r_debug
void* get_final_r_debug(Elf64_Dyn* dt_struct, pid_t pid_child);

// Get program header
void* get_phdr(unsigned long& phent, unsigned long& phnum, pid_t pid_child);

// Recover elf link map address
void* get_link_map(void* rr_debug, pid_t pid, int* status);

// At first, used to print a string from the child.
// Now just returns a pointer to a copy of the latter.
void* print_string_from_mem(void* str, pid_t pid);

// Inject breakpoints into dynamically allocated memory
void browse_link_map(void* link_m, pid_t pid, Breaker* b);

// Check for syscalls
int disass(const char* name, void* phdr, long len, Breaker& b, pid_t pid);

// Recover offsets from sections in ELF
std::pair<off_t, long>get_sections(const char* lib_name, Breaker& b);

#endif /* !LEVEL2_HH */
