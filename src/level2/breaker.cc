#include "level2.hh"

static struct r_debug* get_r_debug(pid_t pid)
{
  // Open proc/[pid]/auxv
  std::ostringstream ss;
  ss << "/proc/" << pid << "/auxv";
  auto file = ss.str();
  int fd = open(file.c_str(), std::ios::binary);
  ElfW(auxv_t) auxv_;

  void* at_phdr  = 0;
  unsigned long at_phent = 0;
  unsigned long at_phnum = 0;
  Elf64_Phdr* phdr;

  // Read from flux until getting all the interesting data
  while (read(fd, &auxv_, sizeof (auxv_)) > -1)
  {
    if (auxv_.a_type == AT_PHDR)
      at_phdr = reinterpret_cast<void*>(auxv_.a_un.a_val);

    if (auxv_.a_type == AT_PHENT)
      at_phent = auxv_.a_un.a_val;

    if (auxv_.a_type == AT_PHNUM)
      at_phnum = auxv_.a_un.a_val;

    if (at_phnum && at_phent && at_phdr)
      break;
  }

  close(fd);

  // Something went wrong ?
  if (!at_phdr)
    return NULL;

  // Binary not an ELF ?
  // FIXME : Get Ehdr
  //if (!is_elf(auxv_))
  //  return NULL;

  // Loop on the Program header until the PT_DYNAMIC entry
  unsigned i;
  for (i = 0; i < at_phnum; ++i)
  {
    phdr = reinterpret_cast<Elf64_Phdr*>((char*)at_phdr + i * at_phent);
    if (phdr->p_type == PT_DYNAMIC)
      break;
  }

  if (i >= at_phnum)
    throw std::logic_error("PT_DYNAMIC not found");

  // First DT_XXXX entry
  Elf64_Dyn* dt_struct = reinterpret_cast<Elf64_Dyn*>(phdr->p_vaddr);

  int i2 = 0;

  // Loop until DT_DEBUG
  while (dt_struct[i2].d_tag != DT_DEBUG)
 ++i2;

  // FIXME : Remove debug fprintf
  fprintf(OUT, "r_debug at %p\n",
          reinterpret_cast<void*>(dt_struct[i2].d_un.d_ptr));

  // Return r_debug struct address
  return reinterpret_cast<struct r_debug*>(dt_struct[i2].d_un.d_ptr);

}

Breaker::Breaker(std::string binary_name, pid_t p)
{
  pid = p;
  r_deb = get_r_debug(pid);
  name = binary_name;
  if (!r_deb)
  {
    fprintf(OUT, "%sERROR:%s Recovering r_debug struct failed\n", RED, NONE);
    throw std::logic_error("r_debug not found. Statically linked perhaps ?");
  }

  brk = reinterpret_cast<void*>(r_deb->r_brk);
}

void Breaker::remove_breakpoint(void* addr)
{
  if (handled_syscalls.find(addr) == handled_syscalls.end())
    return; // No breakpoint found at this address

  // Get saved instruction and rewrite it in memory
  ptrace(PTRACE_POKEDATA, pid, addr, handled_syscalls.find(addr)->second);

  handled_syscalls.erase(addr);
}

void Breaker::add_breakpoint(void* addr)
{
  if (handled_syscalls.find(addr) != handled_syscalls.end())
    return; // Address already patched

  // Get origin instruction and save it
  unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);

  handled_syscalls.insert(std::pair<void*, unsigned long>(addr, instr));

  // Replace it with an int3 (CC) opcode sequence
  ptrace(PTRACE_POKETEXT, pid, addr, (instr & TRAP_MASK) | TRAP_INST);
}

void Breaker::print_bps() const
{
  int i = 0;
  for (auto& iter : handled_syscalls)
  {
    unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, iter.first, 0);
    if (iter.first == brk)
      fprintf(OUT, "%3d: %p (r_brk):\n", i, iter.first);
    else
      fprintf(OUT, "%3d: %p :\n", i, iter.first);

    fprintf(OUT, "\t%8lx (origin)\n", iter.second);
    fprintf(OUT, "\t%8lx (actual)\n", instr);
  }
}

ssize_t Breaker::find_syscalls(void* addr)
{
  constexpr int page_size = 4096;
  struct iovec local[1];
  struct iovec remote[1];
  char buf[page_size];
  ssize_t nread;

  local[0].iov_base = buf;
  local[0].iov_len = 10;
  remote[0].iov_base = addr;
  remote[0].iov_len = page_size;

  nread = process_vm_readv(pid, local, 1, remote, 1, 0);

  return nread;
}
