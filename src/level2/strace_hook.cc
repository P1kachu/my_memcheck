#include "level2.hh"

struct r_debug* get_r_debug(pid_t pid)
{
  std::ostringstream ss;
  ss << "/proc/" << pid << "/auxv";
  auto file = ss.str();
  int fd = open(file.c_str(), std::ios::binary);
  ElfW(auxv_t) auxv_;

  void* at_phdr  = 0;
  unsigned long at_phent = 0;
  unsigned long at_phnum = 0;
  Elf64_Phdr* phdr;

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

  if (!at_phdr)
  {
    fprintf(OUT, "%sERROR:%s Recovering r_debug struct failed\n", RED, NONE);
    return NULL;
  }

  for (unsigned i = 0; i < at_phnum; ++i)
  {
    phdr = reinterpret_cast<Elf64_Phdr*>((char*)at_phdr + i * at_phent);
    if (phdr->p_type == PT_DYNAMIC)
      break;
  }

  Elf64_Dyn* dt_struct = reinterpret_cast<Elf64_Dyn*>(phdr->p_vaddr);

  int i = 0;

  while (dt_struct[i].d_tag != DT_DEBUG)
  ++i;

  fprintf(OUT, "r_debug at %p\n",
          reinterpret_cast<void*>(dt_struct[i].d_un.d_ptr));

  return reinterpret_cast<struct r_debug*>(dt_struct[i].d_un.d_ptr);

}
