#ifndef HELPERS_HH
# define HELPERS_HH

# include "defines.hh"

bool binary_exists(const std::string& name);
bool is_elf(Elf64_Ehdr *hdr);

#endif /* !HELPERS_HH */
