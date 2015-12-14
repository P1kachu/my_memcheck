#include "level3.hh"

Tracker::Tracker(std::string binary_name, pid_t child)
{
        this->pid = child;
        this->name = binary_name;
}

bool Tracker::of_interest(int syscall) const
{
        return syscall == MMAP_SYSCALL || syscall == MREMAP_SYSCALL
                || syscall == MUNMAP_SYSCALL || syscall == MPROTECT_SYSCALL
                || syscall == BRK_SYSCALL;
}
