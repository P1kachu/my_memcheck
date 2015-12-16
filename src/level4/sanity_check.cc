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
		printf("%lx\t", insn[0].address);
		for (int k = 0; k < 8; k++)
			printf("%02x ", insn[0].bytes[k]);
		printf("\t\t%s\t%s\n", insn[0].mnemonic, insn[0].op_str);

		cs_free(insn, count);
	}
	cs_close(& handle);

}

int sanity_check(pid_t pid, Tracker& t)
{
	unsigned long xip = ptrace(PTRACE_PEEKUSER, pid, 0, sizeof(long) * INSTR_REG);
	UNUSED(t);
	print_instruction(xip);
	return 0;
}
