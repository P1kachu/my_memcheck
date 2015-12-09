#include "level2.hh"

void* get_r_debug()
{
  auto at_phdr = getauxval(AT_PHDR);   // Program header array
  auto at_phent = getauxval(AT_PHENT); // Program header size
  auto at_phnum = getauxval(AT_PHNUM); // Number of program header


  // First Program header
  Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(at_phdr);

  fprintf(OUT, "Phdr %p\n", (void*)phdr);
  fprintf(OUT, "Size: %ld\n", at_phent);
  fprintf(OUT, "Entries: %ld\n\n", at_phnum);

  fprintf(OUT, "PHDR    found at %p: OK\n", (void*)phdr); // TODO Remove

  for (unsigned i = 0; i < at_phnum; ++i)
  {
    phdr = reinterpret_cast<Elf64_Phdr*>(at_phdr + i * at_phent);
    if (phdr->p_type == PT_DYNAMIC)
    {
      fprintf(OUT, "Found\n");
      break;
    }
  }

  fprintf(OUT, "SHDR    found at %p: OK\n", (void*)phdr->p_vaddr); // TODO Remove
  return (void*)0;

}
