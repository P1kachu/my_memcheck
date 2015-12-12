#include "dig_into_mem.hh"

void* get_phdr(unsigned long& phent, unsigned long& phnum, pid_t pid_child)
{
    // Open proc/[pid]/auxv
  std::ostringstream ss;
  printf("Pid %d\n", getpid());
  ss << "/proc/" << pid_child << "/auxv";
  auto file = ss.str();
  int fd = open(file.c_str(), std::ios::binary);
  ElfW(auxv_t) auxv_;

  void* at_phdr;

  // Read from flux until getting all the interesting data
  while (read(fd, &auxv_, sizeof (auxv_)) > -1)
  {
    if (auxv_.a_type == AT_PHDR)
      at_phdr = (void*)auxv_.a_un.a_val;

    if (auxv_.a_type == AT_PHENT)
      phent = auxv_.a_un.a_val;

    if (auxv_.a_type == AT_PHNUM)
      phnum = auxv_.a_un.a_val;

    if (phnum && phent && at_phdr)
      break;
  }
  close(fd);

  return at_phdr;
}
