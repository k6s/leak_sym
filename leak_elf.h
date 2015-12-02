#ifndef LEAK_ELF_H_
# define LEAK_ELF_H_

# include <elf.h>
# include <link.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <stddef.h>

# define BASE_ADDRESS	0x400000

typedef struct s_tables_addr		t_tables_addr;

struct				s_tables_addr
{
	unsigned long	symtab;
	unsigned long	strtab;
	unsigned long	*nchains;
	unsigned long	*symndx;
};

typedef void *(*t_leak_ft)(void *, long addr, size_t len);

Elf64_Ehdr			*leak_elf_ehdr(void *param, t_leak_ft leak_data);
Elf64_Phdr			*leak_elf_phdr_entry(void *param, t_leak_ft leak_data,
										 Elf64_Ehdr *e_hdr, unsigned type);
Elf64_Dyn			*leak_elf_dyn(void *param, t_leak_ft leak_data,
								  Elf64_Phdr *p_hdr, Elf64_Sxword type);
struct link_map		*leak_elf_linkmap(void *param, t_leak_ft leak_data,
									  Elf64_Dyn *got);
t_tables_addr		*leak_elf_tables(void *param, t_leak_ft leak_data,
									 struct link_map *link_map);
Elf64_Addr			leak_elf_symbol_addr(void *param, t_leak_ft leak_data,
										 struct link_map *link_map,
										 t_tables_addr *s_tables, char *name);

/*
 * Does all the work by calling the functions below.
 */
Elf64_Addr			leak_elf_sym_addr(int pid, t_leak_ft leak_ft,
									  char *symname);
#endif
