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
    fprintf(OUT, "SHDR    found at %p\n", (void*)phdr->p_vaddr); // TODO Remove
    if (phdr->p_type == PT_LOAD)
    {
      for (unsigned j = 0; j < phdr->p_memsz / sizeof (Elf64_Shdr); ++j)
      {
        Elf64_Shdr* shdr = reinterpret_cast<Elf64_Shdr*>(j * sizeof (Elf64_Shdr) + phdr->p_vaddr);
        fprintf(OUT, "%p --> PT_LOAD (sh_type: %d)\n", (void*)shdr, shdr->sh_type); // TODO Remove
        if (shdr->sh_type == SHT_DYNAMIC)
        {
          fprintf(OUT, "Found\n");
          break;
        }
      }
    }
  }

  Elf64_Shdr* shdr = reinterpret_cast<Elf64_Shdr*>(phdr->p_vaddr);
  if (shdr)
    fprintf(OUT, "SHDR    found at %p: OK\n", (void*)shdr); // TODO Remove
  else
    fprintf(OUT, "Fuck.\n"); // TODO Remove
  return (void*)0;

}
