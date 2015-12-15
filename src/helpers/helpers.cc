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

char* get_cmd_opt(char** begin, char** end, const std::string& option)
{
        char** itr = std::find(begin, end, option);

        if (itr != end && ++itr != end)
                return *itr;
        return NULL;
}

bool cmd_opt_exists(char** begin, char** end, const std::string& option)
{
        return std::find(begin, end, option) != end;
}

void lvl3_print_brk(int prefix, void* origin_break, void* actual_break)
{
        if (!prefix)
        {
                long len = origin_break ? (char*)actual_break - (char*)origin_break : 0;
                fprintf(OUT, "brk { addr = %p, len = 0x%lx, prot = 3 }\n",
                        (void*)actual_break, len);
        }
        else
        {
                long len = origin_break ? (char*)actual_break - (char*)origin_break : 0;
                fprintf(OUT, " to { addr = %p, len = 0x%lx, prot = 3 }\n",
                        (void*)actual_break, len);

        }
}
