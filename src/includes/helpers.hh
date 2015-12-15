#ifndef HELPERS_HH
# define HELPERS_HH

# include "defines.hh"

bool binary_exists(const std::string& name);
bool is_elf(Elf64_Ehdr* hdr);
char* get_cmd_opt(char** begin, char** end, const std::string& option);
bool cmd_opt_exists(char** begin, char** end, const std::string& option);

void lvl3_print_brk(int prefix, void* origin_break, void* actual_break);
void lvl3_print_mremap(int prefix, long addr, long len, int prot);
#endif /* !HELPERS_HH */
