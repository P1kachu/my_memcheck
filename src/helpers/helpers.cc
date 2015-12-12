#include "helpers.hh"

bool binary_exists(const std::string& name)
{
        return (access(name.c_str(), F_OK) != -1);
}

bool is_elf(Elf64_Ehdr* hdr)
{
        return hdr->e_ident[EI_MAG0] == ELFMAG0
                && hdr->e_ident[EI_MAG1] == ELFMAG1
                && hdr->e_ident[EI_MAG2] == ELFMAG2
                && hdr->e_ident[EI_MAG3] == ELFMAG3;
}
