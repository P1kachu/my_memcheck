#include "level4.hh"

static int get_last_instruction(pid_t pid, unsigned long xip)
{
        errno = 0;
        csh handle;
        cs_insn* insn = NULL;
        size_t count = 0;
        struct iovec local;
        struct iovec remote;

        int counter = 0;
	unsigned char buffer[16];
	local.iov_base  = &buffer;
	local.iov_len   = 16;
	remote.iov_base = xip;
	remote.iov_len  = 16;
	int nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	count = cs_disasm(handle, buffer, nread,
			  (uintptr_t)offset + PAGE_SIZE * i, 0, &insn);

	if (count > 0)
	{

		cs_free(insn, count);
	}
	else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(& handle);
	return 0;

}

int remove_page_protection(pid_t pid, Tracker& t)
{
	for (auto it = t.mapped_areas.begin(); it != t.mapped_areas.end(); it++)
		set_page_protection(it->mapped_begin, it->mapped_length,
				       PROT_EXEC, pid);
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

	ptrace(PTRACE_GETREGS, pid, 0, &regs);

	ptrace(PTRACE_SETREGS, pid, 0, &bckp);
	ptrace(PTRACE_POKEDATA, pid, regs.rip, overriden);
	return 0;
}

int handle_injected_sigsegv(pid_t pid, Tracker& t)
{
	reset_page_protection(pid, t);

	int status = 0;
	struct user_regs_struct regs;

	ptrace(PTRACE_GETREGS, pid, 0, &regs);

	int last_instuction = get_last_instruction(pid);

	regs.XIP--;

	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
        printf(" - %p - ", (void*)regs.XIP);

	ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
	waitpid(pid, &status, 0);
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
        printf(" - %p - ", (void*)regs.XIP);

	return remove_page_protection(pid, t);
}

int handle_injected_syscall(int syscall, Breaker& b, void*  bp, Tracker& t)
{
	printf("Syscall : %p\n", bp);
	reset_page_protection(b.pid, t);
	t.handle_syscall(syscall, b, bp);
	return remove_page_protection(b.pid, t);
}
