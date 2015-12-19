#include "level4.hh"

static inline void invalid_memory_access(void* fault, pid_t pid, int size)
{
        fprintf(OUT,
		"[%d] %sInvalid memory access%s of size %d at address: %p\n",
		pid, PRED, NONE, size, fault);
}

static inline void invalid_memory_write(void* fault, pid_t pid, int size)
{
        fprintf(OUT,
		"[%d] %sInvalid memory write%s of size %d at address: %p\n",
		pid, PRED, NONE, size, fault);
}

static inline void invalid_memory_read(void* fault, pid_t pid, int size)
{
        fprintf(OUT,
		"[%d] %sInvalid memory read%s of size %d at address: %p\n",
		pid, PRED, NONE, size, fault);
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

static int get_size(char* instru)
{
	std::string s(instru);
	if (s.find("qword") != std::string::npos)
		return sizeof(long);
	else if(s.find("dword") != std::string::npos)
		return sizeof(int);
	else if(s.find("word") != std::string::npos)
		return sizeof(short);
	else if (s.find("byte") != std::string::npos)
		return sizeof(char);

	return 0;
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

//	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, buffer, 16, xip, 0, &insn);

        if (count > 0)
        {
                if (print)
		{

			int size = get_size(insn[0].op_str);
			if (!segfault)
			{
				int write = insn[0].detail->regs_write_count;
				int read = insn[0].detail->regs_read_count;
				// Read and write
				if ((write && read) || (!write && !read))
					invalid_memory_access(fault, pid, size);

				// Invalid read
				else if (read)
					invalid_memory_read(fault, pid, size);

				// Invalid write
				else
					invalid_memory_write(fault, pid, size);
			}
			else
				invalid_memory_access(fault, pid, size);

			printf("[%d] 0x%lx:\t", pid, xip);

			for (int i = 0; i < 8; ++i)
				printf("%02x ", buffer[i]);

			printf("\t%s %s\033[0m\n",
			       insn[0].mnemonic, insn[0].op_str);
			PID(pid);
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
        unsigned long long heap_sum = 0;
        unsigned long long leak_sum = 0;
        int heap = 0;
        int blocks = 0;

        for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
        {
                blocks++;
                if (it->mapped_protections == MALLOC_CHILD)
		{
			heap_sum += it->mapped_length;
			++heap;
		}
		leak_sum += it->mapped_length;

        }

	fprintf(OUT, "[%d] HEAP LEAKS\n", t.pid);
	fprintf(OUT,"[%d]         Used at exit: %lld byte(s) in %d block(s)\n",
		t.pid, heap_sum, heap);

	if (heap_sum)
	{
		fprintf(OUT,"[%d]         Total heap usage: %d allocs, %d free(s).\n",
			t.pid, t.nb_of_allocs, t.nb_of_frees);

		PID(t.pid);

		fprintf(OUT,
			"[%d] Memory leaks: %s0x%llx%s (%lld) bytes not freed at exit\n",
			t.pid, leak_sum ? RED : GREEN, leak_sum, NONE, leak_sum);
	}
	else
                fprintf(OUT, "[%d]         Each allocated byte on heap was freed, memory clean\n",
			t.pid);

        if (leak_sum)
                fprintf(OUT, "[%d]       in %d block(s)\n", t.pid, blocks);
        else
        {
                fprintf(OUT, "[%d]         Each allocated byte was freed, memory clean\n", t.pid);
                return 0;
        }
        for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
                        fprintf(OUT, "[%d]       * 0x%lx\t - length: 0x%lx\n",
                                t.pid, it->mapped_begin, it->mapped_length);
        return leak_sum;
}
