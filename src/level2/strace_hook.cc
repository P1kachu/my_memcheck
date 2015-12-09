#include "level2.hh"

void* get_r_debug()
{
  auto at_phdr = getauxval(AT_PHDR);   // Program header array
  auto at_phent = getauxval(AT_PHENT); // Program header size
  auto at_phnum = getauxval(AT_PHNUM); // Number of program header


  fprintf(OUT, "PHDR %ld\n", at_phdr);
  fprintf(OUT, "Size: %ld\n", at_phent);
  fprintf(OUT, "Entries: %ld\n\n", at_phnum);

  // First Program header
  Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(at_phdr);


  fprintf(OUT, "PHDR    found at %p: OK\n", (void*)phdr); // TODO Remove

  for (unsigned i = 0; i < at_phnum; ++i)
  {
    phdr = reinterpret_cast<Elf64_Phdr*>(at_phdr + i * at_phent);

    if (phdr->p_type == PT_LOAD)
    {
      Elf64_Shdr* shdr = reinterpret_cast<Elf64_Shdr*>(phdr->p_vaddr);
    fprintf(OUT, "SHDR->sh_type: %d\n", shdr->sh_type); // TODO Remove
      if (shdr->sh_type == SHT_DYNAMIC)
      {
        fprintf(OUT, "Found\n");
        break;
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
