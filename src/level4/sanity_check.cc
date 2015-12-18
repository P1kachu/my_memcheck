#include "level4.hh"

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
		{
			printf("\033[31;1m%p: KO\033[0m ", fault);
			return false;
		}
	}
//	printf("\033[32;1mOK\033[0m ");
	return true;
}

static int print_instruction(unsigned long xip)
{
	csh handle;
	cs_insn* insn = NULL;
	size_t count = 0;
	int ret = 0;
	unsigned char buffer[16] = { 0 };

	for (int i = 1; i < 9; ++i)
		buffer[i] = (xip >> (8 * (8 - i))) & 0xFF;


	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -(printf("CS_OPEN BUG\n"));

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	count = cs_disasm(handle, buffer, 8, 0, 0, &insn);

	if (count > 0)
	{
		printf("%s %s\033[0m\n", insn[0].mnemonic, insn[0].op_str);
		ret = insn[0].size;
		cs_free(insn, count);
	}
	cs_close(& handle);

	return ret;

}


static int exit_with_segfault(pid_t pid, Tracker& t, void* fault)
{
	fprintf(OUT, "[%d] Invalid memory access of size X at address: %p\n", pid, fault);
	fprintf(OUT, "[%d] Process terminating with default action of signal 11 (SIGSEGV)\n", pid);

	display_memory_leaks(t);
	fprintf(OUT, "\n[%d] Segmentation fault\n", pid);
	fflush(0);
	exit(-1);
}


int sanity_customs(pid_t pid, Tracker& t, int handler)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	long instruction_p = regs.XIP;
	siginfo_t infos;
	ptrace(PTRACE_GETSIGINFO, pid, 0, &infos);

	void* fault = infos.si_addr;

	int status = 0;

	if (handler == SEGFAULT)
		return exit_with_segfault(pid, t, fault);

	if (is_valid(fault, t, infos.si_code))
		status =  1;


	if (!status)
	{
		fprintf(OUT, "Invalid memory access of size X at address: %p\n", fault);
		print_instruction(instruction_p);
	}

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

	fprintf(OUT, "\n[%d] Memory leaks: %s0x%llx%s (%lld) bytes not freed at exit\n", t.pid, sum ? RED : GREEN, sum, NONE, sum);
 	fprintf(OUT, "[%d]              in %d blocks - %d on the heap\n", t.pid, blocks, heap);
	if (!sum)
	{
		fprintf(OUT, "[%d]               Each allocated byte was freed, memory clean\n", t.pid);
		return 0;
	}
	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
	{
		if (it->mapped_protections == MALLOC_CHILD)
			fprintf(OUT, "[%d]               * address: 0x%lx\t - length: 0x%lx    \t - Heap\n",
				t.pid, it->mapped_begin, it->mapped_length);
		else
			fprintf(OUT, "[%d]               * address: 0x%lx\t - length: 0x%lx\n",
				t.pid, it->mapped_begin, it->mapped_length);

	}
	return sum;
}
