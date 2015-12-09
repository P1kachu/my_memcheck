#include "level2.hh"

void* get_r_debug(pid_t pid)
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

  while(read(fd, &auxv_, sizeof (auxv_)) > -1)
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

  for (unsigned i = 0; i < at_phnum; ++i)
  {
    phdr = reinterpret_cast<Elf64_Phdr*>((char*)at_phdr + i * at_phent);
    if (phdr->p_type == PT_DYNAMIC)
    {
      fprintf(OUT, "Found (%p)\n", (void*)phdr->p_vaddr);
    }
  }
  return (void*)0;

}
