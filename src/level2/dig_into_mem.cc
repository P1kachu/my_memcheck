#include "dig_into_mem.hh"

void* get_r_brk(void* rr_debug, pid_t pid_child)
{
        struct iovec local;
        struct iovec remote;
        char buffer[128] = { 0 };
        local.iov_base = buffer;
        local.iov_len  = sizeof (struct r_debug);;
        remote.iov_base = rr_debug;
        remote.iov_len  = sizeof (struct r_debug);

        process_vm_readv(pid_child, &local, 1, &remote, 1, 0);

        return (void*)reinterpret_cast<struct r_debug*>(buffer)->r_brk;
}

void* get_final_r_debug(Elf64_Dyn* dt_struct, pid_t pid_child)
{
        Elf64_Dyn child_dyn;
        struct iovec local;
        struct iovec remote;

        // Loop until DT_DEBUG
        local.iov_base = &child_dyn;
        local.iov_len = sizeof (Elf64_Dyn);
        remote.iov_base = dt_struct;
        remote.iov_len  = sizeof (Elf64_Dyn);

        while (true)
        {
                for (Elf64_Dyn* cur = dt_struct; ; ++cur)
                {
                        remote.iov_base = cur;
                        process_vm_readv(pid_child, &local, 1, &remote, 1, 0);
                        if (child_dyn.d_tag == DT_DEBUG)
                                break;
                }
                if (child_dyn.d_un.d_ptr)
                        break;

                ptrace(PTRACE_SINGLESTEP, pid_child, NULL, NULL);
                waitpid(pid_child, 0, 0);
        }

        return reinterpret_cast<void*>(child_dyn.d_un.d_ptr);

}

void* get_pt_dynamic(unsigned long phent, unsigned long phnum,
                     pid_t pid_child, void* at_phdr)
{
        // Loop on the Program header until the PT_DYNAMIC entry
        Elf64_Dyn* dt_struct = NULL;
        struct iovec local;
        struct iovec remote;
        char buffer[128];
        Elf64_Phdr* phdr;
        for (unsigned i = 0; i < phnum; ++i)
        {
                local.iov_base = buffer;
                local.iov_len  = sizeof (Elf64_Phdr);
                remote.iov_base = (char*)at_phdr + i * phent;
                remote.iov_len  = sizeof (Elf64_Phdr);

                process_vm_readv(pid_child, &local, 1, &remote, 1, 0);

                phdr = reinterpret_cast<Elf64_Phdr*>(buffer);
                if (phdr->p_type == PT_DYNAMIC)
                {
                        // First DT_XXXX entry
                        dt_struct =
                                reinterpret_cast<Elf64_Dyn*>(phdr->p_vaddr);
                        break;
                }
        }

        if (!dt_struct)
                throw std::logic_error("PT_DYNAMIC not found");

        // FIXME : Deadcode
        // printf("Found _DYNAMIC:\t\t%p\n", (void*)dt_struct);
        return (void*) dt_struct;
}


void* get_phdr(unsigned long& phent, unsigned long& phnum, pid_t pid_child)
{
        // Open proc/[pid]/auxv
        std::ostringstream ss;
        ss << "/proc/" << pid_child << "/auxv";
        auto file = ss.str();
        int fd = open(file.c_str(), std::ios::binary);
        ElfW(auxv_t) auxv_;

        void* at_phdr;

        // Read from flux until getting all the interesting data
        while (read(fd, &auxv_, sizeof (auxv_)) > -1)
        {
                if (auxv_.a_type == AT_PHDR)
                        at_phdr = (void*)auxv_.a_un.a_val;

                if (auxv_.a_type == AT_PHENT)
                        phent = auxv_.a_un.a_val;

                if (auxv_.a_type == AT_PHNUM)
                        phnum = auxv_.a_un.a_val;

                if (phnum && phent && at_phdr)
                        break;
        }
        close(fd);

        return at_phdr;
}

void* get_link_map(void* rr_debug, pid_t pid, int* status)
{
        char buffer[128];
        struct iovec local;
        struct iovec remote;
        local.iov_base  = buffer;
        local.iov_len   = sizeof (struct r_debug);
        remote.iov_base = rr_debug;
        remote.iov_len  = sizeof (Elf64_Phdr);

        process_vm_readv(pid, &local, 1, &remote, 1, 0);

        struct link_map* link_map = ((struct r_debug*)buffer)->r_map;

        // FIXME : Deadcode
        // fprintf(OUT, "Found r_debug->r_map:\t\t%p\n", (void*)link_map);
        *status = ((struct r_debug*)buffer)->r_state;
        return link_map;
}

void *print_string_from_mem(void* str, pid_t pid)
{
        char s[64] = {0};
        struct iovec local;
        struct iovec remote;
        local.iov_base  = &s;
        local.iov_len   = sizeof (struct link_map);
        remote.iov_base = str;
        remote.iov_len  = sizeof (struct link_map);

        ssize_t read = process_vm_readv(pid, &local, 1, &remote, 1, 0);

        if (read)
        {
                fprintf(OUT, "%s\n", s);
                return strdup(s);
        }
        return NULL;
}

std::pair<off_t, long>get_sections(const char* lib_name)
{
        int fd = open(lib_name, O_RDONLY);
        if (fd < 0)
        {
                fprintf(OUT, "%sERROR%s Couldn't open lib %s\n", RED, NONE, lib_name);
                return std::pair<off_t, int>(0,0);
        }

        ElfW(Ehdr) elf_header;
        ElfW(Shdr) section_header;
        ElfW(Shdr) string_header;
        bool in_executable = false;
        off_t offset = 0;
        long len = 0;
        // Elf header
        unsigned nread = read(fd, &elf_header, sizeof (ElfW(Ehdr)));

        // String table offset
        lseek(fd, elf_header.e_shoff, SEEK_CUR);
        int string_table_offset =  elf_header.e_shstrndx;
        lseek(fd, elf_header.e_shentsize * (string_table_offset - 1), SEEK_CUR);

        // String table
        nread = read(fd, &string_header, sizeof (ElfW(Shdr)));
        off_t strtab = string_header.sh_offset;
        lseek(fd, strtab, SEEK_SET);
        char* table = new char[MAX_STRING_SIZE * elf_header.e_shnum];
        nread = read(fd, table, sizeof (char) * MAX_STRING_SIZE * elf_header.e_shnum);

        // Section headers
        int i;
        for (i = 0; i < elf_header.e_shnum; ++i)
        {
                char buff[255] = { 0 };
                lseek(fd, elf_header.e_shoff + elf_header.e_shentsize * i, SEEK_SET);

                nread = read(fd, &section_header, sizeof (ElfW(Shdr)));

                if (in_executable && !(section_header.sh_flags & SHF_EXECINSTR))
                        break;

                if (!in_executable && section_header.sh_flags & SHF_EXECINSTR)
                {
                        offset = section_header.sh_offset;
                        in_executable = true;
                }

                if (in_executable)
                {
                        len += section_header.sh_size;
                        for (int j = section_header.sh_name; table[j] != '\0'; ++j)
                                buff[j - section_header.sh_name] = table[j];

                        fprintf(OUT, "%s - EX: %ld\n", buff, section_header.sh_flags & SHF_EXECINSTR);
                }

                lseek(fd, elf_header.e_shentsize, SEEK_CUR);
        }

        UNUSED(nread);

        return std::pair<off_t, long>(offset, len);
}

int disass(const char* name, void* offset, long len, Breaker b, pid_t pid)
{
        printf("Disassembling %ld bytes of code at %p\n", len, offset);
        errno = 0;
        csh handle;
        cs_insn *insn = NULL;
        size_t count = 0;
        struct iovec local;
        struct iovec remote;


        for (unsigned i = 0; i < len / PAGE_SIZE + 1; ++i)
        {
                unsigned char buffer[PAGE_SIZE];
                local.iov_base  = &buffer;
                local.iov_len   = PAGE_SIZE;
                remote.iov_base = offset + i * PAGE_SIZE;
                remote.iov_len  = PAGE_SIZE;
                int nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);

                if (nread < 0)
                        return -1;
                print_errno();

                if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
                        return -1;

                cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
                count = cs_disasm(handle, buffer, nread - 1, (uintptr_t)offset, 0, &insn);

                if (count > 0)
                {
                        for (size_t j = 0; j < count; j++)
                        {
                                printf("%lx\t", insn[j].address);
                                for (int k = 0; k < insn[j].size; k++)
                                        printf("%x",insn[j].bytes[k]);
                                printf("\t\t%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
                                auto id = insn[j].id;

                                // If syscall, add breakpoint
                                if (id == X86_INS_SYSENTER || id == X86_INS_SYSCALL
                                    || (id == X86_INS_INT && insn[j].bytes[1] == 0x80))
                                        b.add_breakpoint(name, reinterpret_cast<void*>(insn[j].address));
                        }

                        cs_free(insn, count);
                }
                else
                        printf("ERROR: Failed to disassemble given code!\n");
                cs_close(&handle);
        }
        return 0;
}

void browse_link_map(void* link_m, pid_t pid, Breaker* b)
{
        struct link_map map;
        struct iovec local;
        struct iovec remote;
        local.iov_base  = &map;
        local.iov_len   = sizeof (struct link_map);
        remote.iov_base = link_m;
        remote.iov_len  = sizeof (struct link_map);

        process_vm_readv(pid, &local, 1, &remote, 1, 0);

        fprintf(OUT, "\n%sBrowsing link map%s:\n", YELLOW, NONE);

        // FIXME : Useless ? Check if we missed some
        while (map.l_prev)
        {
                remote.iov_base = map.l_prev;
                process_vm_readv(pid, &local, 1, &remote, 1, 0);
        }

        do
        {
                process_vm_readv(pid, &local, 1, &remote, 1, 0);
                if (map.l_addr)
                {
                        fprintf(OUT, "%sl_name%s: ",  GREEN, NONE);

                        // Unlike what the elf.h file can say about it
                        // l_addr is not a difference or any stewpid thing
                        // like that apparently, but the base address the
                        // shared object is loaded at.
                        char* dupp = (char*)print_string_from_mem(map.l_name, pid);

                        std::pair<off_t, long> sections = get_sections(dupp);
                        if (sections.second)
                                disass(dupp, (char*)map.l_addr + sections.first, sections.second, *b, pid);

                        free(dupp);
                        fprintf(OUT, "\n");
                }
                remote.iov_base = map.l_next;
        } while (map.l_next);

        fprintf(OUT, "\n");
        b->print_bps();
        exit(0);
}
