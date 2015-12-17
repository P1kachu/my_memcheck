#include "level4.hh"

static int print_instruction(unsigned long xip, void* faulty)
{
        csh handle;
        cs_insn* insn = NULL;
        size_t count = 0;
	int ret = 0;
	unsigned char buffer[8] = { 0 };

	for (int i = 0; i < 8; ++i)
	{
		buffer[i] = (xip >> (8 * (8 - i))) & 0xFF;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
	{
		printf("CS_OPEN BUG\n");
		return -1;
	}

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	count = cs_disasm(handle, buffer, 8, 0, 0, &insn);

	if (count > 0)
	{
		printf("\033[33;1m%lx ", insn[0].address);
		for (int k = 0; k < 8; k++)
			printf("%02x ", insn[0].bytes[k]);
		printf("%s %s\033[0m (faulty: %p)\n", insn[0].mnemonic, insn[0].op_str, faulty);
		ret = insn[0].size;
		cs_free(insn, count);
	}
	cs_close(& handle);

	return ret;

}

static bool is_valid(void* segv_addr, Tracker& t)
{
	if (segv_addr == (void*)0xff)
	printf("----------------------\n");
	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
                if (it->area_contains((unsigned long)segv_addr))
                        return true;
        return false;

}

int sanity_check(pid_t pid, Tracker& t, void* seg_addr)
{
	static long previous = get_xip(pid);
	siginfo_t infos;

	ptrace(PTRACE_GETSIGINFO, pid, 0, &infos);

	long tmp = get_xip(pid);
	void* faulty = infos.si_addr;

	if (!is_valid(faulty, t))
	{
		printf("\033[31;1mINVALID\033[0m ");
		printf("\033[33;1mMemory access (%p)\033[0m - ", seg_addr);
	        print_instruction((unsigned long)infos.si_addr, faulty);
	}
	else
	{
		printf("\033[32;1mVALID\033[0m ");
		printf("\033[33;1mMemory access (%p)\033[0m\n", seg_addr);

	}

	if (1 && tmp == previous)
	{
		ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
		waitpid(pid, 0, 0);
	}

	previous = get_xip(pid);


	return 0;
}
