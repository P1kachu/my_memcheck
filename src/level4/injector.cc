#include "level4.hh"

int remove_page_protection(pid_t pid, Tracker& t)
{
	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
		set_page_protection(it->mapped_begin, it->mapped_length,
				    PROT_EXEC * it->executable_bit, pid);

	return 0;
}

int reset_page_protection(pid_t pid, Tracker& t)
{
	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
		set_page_protection(it->mapped_begin, it->mapped_length,
				    it->mapped_protections, pid);
	return 0;
}

int set_page_protection(unsigned long addr, size_t len, unsigned long prot, pid_t pid)
{
	struct user_regs_struct regs;
	struct user_regs_struct bckp;
	int status = 0;
	unsigned long overriden = 0;

	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	bckp = regs;
	regs.rdi = addr;
	regs.rsi = len;
	regs.rdx = prot;
	regs.rax = MPROTECT_SYSCALL;
	overriden = ptrace(PTRACE_PEEKDATA, pid, regs.rip, sizeof(long));
	ptrace(PTRACE_POKEDATA, pid, regs.rip, SYSCALL);
	ptrace(PTRACE_SETREGS, pid, 0, &regs);


	ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
	waitpid(pid, &status, 0);


	ptrace(PTRACE_SETREGS, pid, 0, &bckp);
	ptrace(PTRACE_POKEDATA, pid, bckp.rip, overriden);
	return 0;
}

int handle_injected_sigsegv(pid_t pid, Tracker& t)
{
	sanity_customs(pid, t, 0);
	reset_page_protection(pid, t);

	int status = 0;
	ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
	waitpid(pid, &status, 0);

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
		sanity_customs(pid, t, SEGFAULT);

	remove_page_protection(pid, t);
	return 0;
}

int handle_injected_syscall(int syscall, Breaker& b, void*  bp, Tracker& t)
{
	bool print = false;
	reset_page_protection(b.pid, t);
	t.handle_syscall(syscall, b, bp, print);
	remove_page_protection(b.pid, t);
	return 0;
}
