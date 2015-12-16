#include "level4.hh"

static void print_instruction(unsigned long xip)
{
        csh handle;
        cs_insn* insn = NULL;
        size_t count = 0;

	unsigned char buffer[8] = { 0 };

	for (int i = 0; i < 8; ++i)
	{
		buffer[i] = (xip >> (8 * (8 - i))) & 0xFF;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
	{
		printf("CS_OPEN BUG\n");
		return;
	}

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	count = cs_disasm(handle, buffer, 8, 0, 0, &insn);

	if (count > 0)
	{
		printf("\033[33;1m%lx ", insn[0].address);
		for (int k = 0; k < 8; k++)
			printf("%02x ", insn[0].bytes[k]);
		printf("\t %s %s\033[0m\n", insn[0].mnemonic, insn[0].op_str);

		cs_free(insn, count);
	}
	cs_close(& handle);

}

static bool is_valid(void* segv_addr, Tracker& t)
{
//	t.print_mapped_areas();
	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
                if (it->area_contains((unsigned long)segv_addr))
                        return true;
        return false;

}

int sanity_check(pid_t pid, Tracker& t, void* seg_addr)
{
	printf("\033[32;1mMemory access (%p)\033[0m - ", seg_addr);
	print_instruction((unsigned long)seg_addr);
	printf("\n\n");

	UNUSED(pid);

	if (is_valid(seg_addr, t))
		printf("\t\033[32;1mVALID\033[0m\n");
	else
		printf("\t\033[31;1mINVALID\033[0m\n");

	printf("\n\n");

	return 0;
}
