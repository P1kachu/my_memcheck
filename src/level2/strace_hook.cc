#include "level2.hh"

void* get_r_debug()
{
  auto at_phdr = getauxv(AT_PHDR);   // Program header array
  auto at_phent = getauxv(AT_PHENT); // Program header size
  auto at_phnum = getauxv(AT_PHNUM); // Number of program header

  // First Program header
  Elf64_Phdr** phdrs = reinterpret_cast<Elf64_Phdr**>(at_phdr);

  for (int i = 0; i < at_phnum; ++i)
  {
    fprintf(OUT, "Phdr p_type: %ld ?= %ld\n", phdrs[i]->p_type, PT_LOAD);
    if (phdrs[i]->p_type, PT_LOAD)
    {
      fprintf(OUT, "Found !\n");
      break;
    }
  }

}
