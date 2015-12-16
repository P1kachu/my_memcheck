#include "level4.hh"

void print_instruction(unsigned long xip)
{
        csh handle;
        cs_insn* insn = NULL;
        size_t count = 0;

	JE FAIS LE FOR LOOP

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
	{
		printf("CS_OPEN BUG\n");
		return;
	}

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	count = cs_disasm(handle, xip, nread, , 0, &insn);

	if (count > 0)
	{
		printf("%lx\t", insn[j].address);
		for (int k = 0; k < 8; k++)
			printf("%02x ", insn[j].bytes[k]);
		printf("\t\t%s\t%s\n", insn[j].mnemonic, insn[j].op_str);

		cs_free(insn, count);
	}
	cs_close(& handle);
        return 0;

}

int sanity_check(pid_t pid, Tracker& t)
{
	unsigned long xip = ptrace(PTRACE_PEEKUSER, pid, 0, sizeof(long) * XIP);
	print_instruction(xip);
}
