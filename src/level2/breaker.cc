#include "level2.hh"

struct r_debug* Breaker::get_r_debug(pid_t pid_child)
{
  // Open proc/[pid]/auxv
  std::ostringstream ss;
  printf("Pid %d\n", getpid());
  ss << "/proc/" << pid_child << "/auxv";
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
      at_phdr = (void*)auxv_.a_un.a_val;

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

  struct iovec local[1];
  struct iovec remote[1];
  ssize_t nread;

  // Loop on the Program header until the PT_DYNAMIC entry
  unsigned i;
  Elf64_Dyn* dt_struct = NULL;
  char buffer[1024] = { 0 };
  for (i = 0; i < at_phnum; ++i)
  {
    local[0].iov_base = buffer;
    local[0].iov_len  = 1024;
    remote[0].iov_base = (char*)at_phdr + i * at_phent;
    remote[0].iov_len  = sizeof (Elf64_Phdr);

    nread = process_vm_readv(pid_child, local, 1, remote, 1, 0);

    phdr = reinterpret_cast<Elf64_Phdr*>(buffer);
    if (phdr->p_type == PT_DYNAMIC)
    {
      // First DT_XXXX entry
      dt_struct = reinterpret_cast<Elf64_Dyn*>(phdr->p_vaddr);
      break;
    }
    memset(buffer, 0, 1024); // FIXME : Usefull ?
  }

  if (!dt_struct)
    throw std::logic_error("PT_DYNAMIC not found");

  printf("Dyn Child:\t\t%p\n", (void*)dt_struct);

  Elf64_Dyn child_dyn;
  // Loop until DT_DEBUG
  local[0].iov_base = &child_dyn;
  local[0].iov_len = sizeof (Elf64_Dyn);
  remote[0].iov_base = dt_struct;
  remote[0].iov_len  = sizeof (Elf64_Dyn);

  while (true)
  {
    for(Elf64_Dyn *cur = dt_struct; ; ++cur)
    {
      remote[0].iov_base = cur;
      nread = process_vm_readv(pid_child, local, 1, remote, 1, 0);
      if (child_dyn.d_tag == DT_DEBUG)
        break;
    }
    if (child_dyn.d_un.d_ptr)
      break;

    ptrace(PTRACE_SINGLESTEP, pid_child, NULL, NULL);
    waitpid(pid_child, 0, 0);
  }

  void* rr_debug = reinterpret_cast<void*>(child_dyn.d_un.d_ptr);
  UNUSED(nread);

  // So fucking annoying ffs
  local[0].iov_base = buffer;
  local[0].iov_len  = sizeof (struct r_debug);;
  remote[0].iov_base = rr_debug;
  remote[0].iov_len  = sizeof (struct r_debug);

  nread = process_vm_readv(pid_child, local, 1, remote, 1, 0);

  rr_brk = (void*)reinterpret_cast<struct r_debug*>(buffer)->r_brk;

  // FIXME : Remove debug fprintf
  fprintf(OUT, "Found r_debug\t\t%p\n", rr_debug);
  fprintf(OUT, "Found r_debug->r_brk\t%p\n", rr_brk);

  // Return r_debug struct address
  return reinterpret_cast<struct r_debug*>(rr_debug);

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
}

void Breaker::remove_breakpoint(const char* region, void* addr)
{
  UNUSED(region);
/*  auto it = handled_syscalls.find(region);

  printf("##%s##\n", it->first);

  if (it == handled_syscalls.end())
  {
    fprintf(OUT, "%sERROR:%s Region %s not found in map (remove)\n", RED, NONE, region);
    return;
  }

  auto breaks = it->second;*/
  auto& breaks = handled_syscalls;

  if (breaks.find(addr) == breaks.end())
    return; // No breakpoint found at this address

  // Get saved instruction and rewrite it in memory
  ptrace(PTRACE_POKEDATA, pid, addr, breaks.find(addr)->second);

  breaks.erase(addr);
  printf("Breakpoint deleted\n");
}

void Breaker::add_breakpoint(const char* region, void* addr)
{
  // Get origin instruction and save it
  unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  UNUSED(region);
  print_errno();
  printf("LLLL\n");
//  auto it = handled_syscalls.find(region);

  /*if (it == handled_syscalls.end())
  {
    printf("LOLO\n");
    std::map<void*, unsigned long>* inner = new std::map<void*, unsigned long>;
    inner->insert(std::make_pair(addr, instr));
    handled_syscalls.insert(std::pair<const char*, std::map<void*, unsigned long>>(region, *inner));
    return;
    }

  //auto breaks = it->second;

  if (breaks.find(addr) != breaks.end())
    return; // Address already patched

  breaks.insert(std::pair<void*, unsigned long>(addr, instr));*/

  // Replace it with an int3 (CC) opcode sequence

//  if (handled_syscalls.find(addr) != handled_syscalls.end())
//    return; // Address already patched

  handled_syscalls.insert(std::pair<void*, unsigned long>(addr, instr));


  ptrace(PTRACE_POKETEXT, pid, addr, (instr & TRAP_MASK) | TRAP_INST);
  printf("Breakpoint added\n");
}

void Breaker::print_bps() const
{
  int i = 0;
/*  for (auto& region : handled_syscalls)
  {
    fprintf(OUT, "%s: ", region.first);
    for (auto& iter : region.second)
    {*/
  for (auto& iter : handled_syscalls)
  {
    unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, iter.first, 0);
    if (iter.first == rr_brk)
      fprintf(OUT, "%3d: %p (r_brk):\n", i, iter.first);
    else
      fprintf(OUT, "%3d: %p :\n", i, iter.first);

    fprintf(OUT, "\t%8lx (origin)\n", iter.second);
    fprintf(OUT, "\t%8lx (actual)\n", instr);
  }
}

/*ssize_t Breaker::find_syscalls(void* addr)
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

  csh handle;
  cs_insn *insn;
  size_t count;


  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;

  count = cs_disasm(handle, buf, nread, 0x1000, 0, &insn);

  if (count > 0)
  {
    size_t j;

    for (j = 0; j < count; j++)
      printf("0x%lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);

    cs_free(insn, count);
  }
  else
    printf("ERROR: Failed to disassemble given code!\n");

  cs_close(&handle);

  return nread;
}
*/
