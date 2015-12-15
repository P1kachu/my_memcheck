#include "level4.hh"

int remove_page_protection(void* addr, size_t len, Tracker t, pid_t pid)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	unsigned long overwritten = ptrace(PTRACE_PEEKDATA, pid, regs.XIP);

	regs.rdi = addr;
	regs.rsi = len;
	regs.rdx = PROT_EXEC;
	ptrace(PTRACE_POKEDATA, pid, regs.XIP, 0x050F);
	ptrace(PTRACE_SETREGS, pid, NULL, regs);

	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	waitpid(pid, 0, 0);


	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	regs.XIP--;
	ptrace(PTRACE_SETREGS, pid, NULL, regs);

	ptrace(PTRACE_POKEDATA, pid, regs.XIP, overwritten);
}
