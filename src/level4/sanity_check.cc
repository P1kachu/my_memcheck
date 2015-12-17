#include "level4.hh"

static bool is_valid(void* fault, Tracker& t)
{
	if (fault == nullptr)
		return true;

	auto it = t.get_mapped(reinterpret_cast<unsigned long> (fault));
	if (it == t.mapped_areas.end())
	{
		printf("\033[31;1mKO\033[0m ");
		return false;
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
		printf("%p: %s %s\033[0m\n\n", (void*)xip, insn[0].mnemonic, insn[0].op_str);
		ret = insn[0].size;
		cs_free(insn, count);
	}
	cs_close(& handle);

	return ret;

}

int sanity_customs(pid_t pid, Tracker& t)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	long instruction_p = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
	siginfo_t infos;

	ptrace(PTRACE_GETSIGINFO, pid, 0, &infos);

	void* fault = infos.si_addr;

	int status = 0;

	if (is_valid(fault, t))
		status =  1;


	if (!status)
	{
		fprintf(OUT, "Invalid memory access of size X at address: %p\n", fault);
		print_instruction(instruction_p);
	}

	infos.si_addr = NULL;

	ptrace(PTRACE_SETSIGINFO, pid, 0, &infos);
	return 1;
}

int display_memory_leaks(Tracker& t)
{
	unsigned long long sum = 0;

//	t.print_mapped_areas();

	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
		sum += it->mapped_length;

	fprintf(OUT, "\nMemory leaks: %s0x%llx%s bytes not freed at exit\n", sum ? RED : GREEN, sum, NONE);

	if (!sum)
	{
		fprintf(OUT, "              Every allocated byte was freed, memory clean\n");
		return 0;
	}
	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
	{
		if (it->mapped_protections == MALLOC_CHILD)
			fprintf(OUT, "              * address: 0x%lx\t - length: 0x%lx    \t - Heap\n",
			it->mapped_begin, it->mapped_length);
		else
			fprintf(OUT, "              * address: 0x%lx\t - length: 0x%lx\n",
				it->mapped_begin, it->mapped_length);

	}
	return sum;
}
