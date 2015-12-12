#include "level2.hh"

struct r_debug* Breaker::get_r_debug(pid_t pid_child)
{
  struct iovec local;
  struct iovec remote;
  unsigned i;
  Elf64_Dyn* dt_struct = NULL;
  char buffer[128] = { 0 };
  Elf64_Phdr* phdr;
  unsigned long at_phent = 0;
  unsigned long at_phnum = 0;
  void* at_phdr  = get_phdr(at_phent, at_phnum, pid_child);

  // Something went wrong ?
  if (!at_phdr)
    return NULL;

  // Binary not an ELF ?
  // FIXME : Get Ehdr, helpers/is_elf

  // FIXME : Refactor this sh*tload

  // Loop on the Program header until the PT_DYNAMIC entry
  for (i = 0; i < at_phnum; ++i)
  {
    local.iov_base = buffer;
    local.iov_len  = sizeof (Elf64_Phdr);
    remote.iov_base = (char*)at_phdr + i * at_phent;
    remote.iov_len  = sizeof (Elf64_Phdr);

    process_vm_readv(pid_child, &local, 1, &remote, 1, 0);

    phdr = reinterpret_cast<Elf64_Phdr*>(buffer);
    if (phdr->p_type == PT_DYNAMIC)
    {
      // First DT_XXXX entry
      dt_struct = reinterpret_cast<Elf64_Dyn*>(phdr->p_vaddr);
      break;
    }
  }

  if (!dt_struct)
    throw std::logic_error("PT_DYNAMIC not found");

  printf("Found _DYNAMIC:\t\t%p\n", (void*)dt_struct);

  Elf64_Dyn child_dyn;
  // Loop until DT_DEBUG
  local.iov_base = &child_dyn;
  local.iov_len = sizeof (Elf64_Dyn);
  remote.iov_base = dt_struct;
  remote.iov_len  = sizeof (Elf64_Dyn);

  while (true)
  {
    for(Elf64_Dyn *cur = dt_struct; ; ++cur)
    {
      remote.iov_base = cur;
      process_vm_readv(pid_child, &local, 1, &remote, 1, 0);
      if (child_dyn.d_tag == DT_DEBUG)
        break;
    }
    if (child_dyn.d_un.d_ptr)
      break;

    ptrace(PTRACE_SINGLESTEP, pid_child, NULL, NULL);
    waitpid(pid_child, 0, 0);
  }

  void* rr_debug = reinterpret_cast<void*>(child_dyn.d_un.d_ptr);

  // So fucking annoying ffs
  local.iov_base = buffer;
  local.iov_len  = sizeof (struct r_debug);;
  remote.iov_base = rr_debug;
  remote.iov_len  = sizeof (struct r_debug);

  process_vm_readv(pid_child, &local, 1, &remote, 1, 0);

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
}

void Breaker::add_breakpoint(const char* region, void* addr)
{
  // Get origin instruction and save it
  unsigned long instr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  UNUSED(region);
  print_errno();
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

  if (handled_syscalls.find(addr) != handled_syscalls.end())
    return; // Address already patched


  handled_syscalls.insert(std::pair<void*, unsigned long>(addr, instr));


  ptrace(PTRACE_POKETEXT, pid, addr, (instr & TRAP_MASK) | TRAP_INST);
}

char Breaker::is_from_us(void* addr) const
{
  return handled_syscalls.find(addr) != handled_syscalls.end();
}

void Breaker::handle_bp(void* addr)
{
  printf("%%rip = %p ", addr);
  if (addr == rr_brk)
  {
    printf("(brk)\n");
    int state = 0;
    void* link_map = get_link_map(r_deb, pid, &state);
    printf("State: %s\n", state ? state > 1 ? "DELETE" : "ADD" : "CONSISTENT");
    browse_link_map(link_map, pid);

  }
  exec_breakpoint(addr);
}

void Breaker::exec_breakpoint(void* addr)
{
  if (handled_syscalls.find(addr) == handled_syscalls.end())
    return; // Not found
  struct user_regs_struct regs;

  ptrace(PTRACE_GETREGS, pid, 0, &regs);
  regs.XIP -= 1;
  ptrace(PTRACE_SETREGS, pid, 0, &regs);

  remove_breakpoint(NULL, addr);
  ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

  int wait_status = 0;
  waitpid(pid, &wait_status, 0);
  if (WIFEXITED(wait_status))
    throw std::logic_error("EXITED");

  add_breakpoint(NULL, addr);
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
