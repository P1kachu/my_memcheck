#include "level4.hh"

static inline void invalid_memory_access(void* fault, pid_t pid)
{
        fprintf(OUT,
		"[%d] %sInvalid memory access%s of size X at address: %p\n",
		pid, PRED, NONE, fault);
}

static inline void invalid_memory_write(void* fault, pid_t pid)
{
        fprintf(OUT,
		"[%d] %sInvalid memory write%s of size X at address: %p\n",
		pid, PRED, NONE, fault);
}

static inline void invalid_memory_read(void* fault, pid_t pid)
{
        fprintf(OUT,
		"[%d] %sInvalid memory read%s of size X at address: %p\n",
		pid, PRED, NONE, fault);
}

static inline void invalid_free_aux(void* fault, pid_t pid, void* pointer)
{
        fprintf(OUT,
		"[%d] %sInvalid free%s of pointer %p at address: %p\n",
		pid, PRED, NONE, pointer, fault);
}

static bool is_valid(void* fault, Tracker& t, int si_code)
{
        UNUSED(si_code);
        if (fault == nullptr || si_code != SEGV_ACCERR)
                return true;

        auto it = t.get_mapped(reinterpret_cast<unsigned long> (fault));
        if (it == t.mapped_areas.end())
        {
                int ret = fault < t.actual_program_break && fault >= t.origin_program_break;
                if (!ret)
                        return false;
        }
//	printf("\033[32;1mOK\033[0m ");
        return true;
}

static int get_instruction(pid_t pid,
			   unsigned long xip,
			   unsigned long long  opcodes,
			   bool print,
			   bool segfault,
			   void* fault)
{
        csh handle;
        cs_insn* insn = NULL;
        size_t count = 0;
        int ret = 0;
        unsigned char buffer[16] = { 0 };

        for (int i = 0; i < 8; ++i)
                buffer[i] = (opcodes >> (8 * i)) & 0xFF;


        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
                return -(printf("CS_OPEN BUG\n"));

        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        count = cs_disasm(handle, buffer, 16, xip, 0, &insn);

        if (count > 0)
        {
                if (print)
		{

			if (!segfault)
			{
				std::string tmp(insn[0].mnemonic);
				if(tmp.find("movzx") != std::string::npos)
					invalid_memory_read(fault, pid);
				else if (tmp.find("mov") != std::string::npos)
					invalid_memory_write(fault, pid);
				else
					invalid_memory_access(fault, pid);
			}
			else
				invalid_memory_access(fault, pid);

			printf("[%d] 0x%lx: ", pid, xip);

			for (int i = 0; i < insn[0].size; ++i)
				printf("%02x ", buffer[i]);

			printf("\t%s %s\033[0m\n",
			       insn[0].mnemonic, insn[0].op_str);
                }
		ret = insn[0].size;
                cs_free(insn, count);
        }
        cs_close(& handle);

        return ret;

}

int invalid_free(pid_t pid, void* pointer, Tracker& t)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, &regs, &regs);
        unsigned long long instruction_p = ptrace(PTRACE_PEEKDATA,
						  pid, regs.XIP,
						  sizeof (unsigned long long));
        siginfo_t infos;
        ptrace(PTRACE_GETSIGINFO, pid, 0, &infos);

        void* fault = infos.si_addr;
	invalid_free_aux(fault, pid, pointer);
	get_instruction(pid, regs.XIP, instruction_p, true, false, fault);
	display_memory_leaks(t);
	exit(-1);

}

int sanity_customs(pid_t pid, Tracker& t, int handler)
{
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, &regs, &regs);
        unsigned long long instruction_p = ptrace(PTRACE_PEEKDATA,
						  pid, regs.XIP,
						  sizeof (unsigned long long));
        siginfo_t infos;
        ptrace(PTRACE_GETSIGINFO, pid, 0, &infos);

        void* fault = infos.si_addr;

        int status = 0;

        if (handler == SEGFAULT)
        {
                int size = get_instruction(pid, regs.XIP, instruction_p, true, true, fault);
                fprintf(OUT, "[%d] Signal 11 caught (SIGSEGV)", pid);
                regs.XIP += size + 1;
                ptrace(PTRACE_SETREGS, pid, 0, &regs);
                return 0;
        }

        if (is_valid(fault, t, infos.si_code))
                status =  1;


        if (!status)
                get_instruction(pid, regs.XIP, instruction_p, true, false, fault);

//	printf("Status : %d\n\tXIP  : %p\n\tFAULT: %p\n", status, (void*)regs.XIP, fault);

        infos.si_addr = NULL;

        ptrace(PTRACE_SETSIGINFO, pid, 0, &infos);
        return 1;
}

int display_memory_leaks(Tracker& t)
{
        unsigned long long sum = 0;
        int heap = 0;
        int blocks = 0;

        for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
        {
                blocks++;
                sum += it->mapped_length;
                if (it->mapped_protections == MALLOC_CHILD)
                       ++heap;

        }

//	t.print_mapped_areas();

        fprintf(OUT, "\n[%d] Memory leaks: %s0x%llx%s (%lld) bytes not freed at exit\n", t.pid, sum ? RED : GREEN, sum, NONE, sum);

        if (sum)
                fprintf(OUT, "[%d]       in %d blocks - %d on the heap\n", t.pid, blocks, heap);
        else
        {
                fprintf(OUT, "[%d]         Each allocated byte was freed, memory clean\n", t.pid);
                return 0;
        }
        for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
        {
                if (it->mapped_protections == MALLOC_CHILD)
                        fprintf(OUT, "[%d]       * 0x%lx\t - length: 0x%lx    \t - Heap\n",
                                t.pid, it->mapped_begin, it->mapped_length);
                else
                        fprintf(OUT, "[%d]       * 0x%lx\t - length: 0x%lx\n",
                                t.pid, it->mapped_begin, it->mapped_length);

        }
        return sum;
}
