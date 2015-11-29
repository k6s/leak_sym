#include <leak_elf.h>

Elf64_Ehdr				*leak_elf_ehdr(void *param, t_leak_ft leak_data)
{
	Elf64_Ehdr			*e_hdr;

	if (!(e_hdr = leak_data(param, 0x400000, sizeof(Elf64_Ehdr))))
		return (NULL);
	if (!(e_hdr->e_entry & 0x400000)
		|| (e_hdr->e_entry & 0xff00000000000000))
	{
		free(e_hdr);
		return (NULL);
	}
	return (e_hdr);
}

Elf64_Phdr				*leak_elf_phdr_entry(void *param, t_leak_ft leak_data,
											 Elf64_Ehdr *e_hdr,
											 Elf64_Word type)
{
	Elf64_Phdr			*p_hdr;
	ssize_t				i;

	if (!(p_hdr = leak_data(param, e_hdr->e_phoff + 0x400000, sizeof(*p_hdr))))
		return (NULL);
	i = sizeof(*p_hdr);
	while (p_hdr->p_type != type && i < e_hdr->e_phentsize * e_hdr->e_phnum)
	{
		free(p_hdr);
		if (!(p_hdr = leak_data(param, e_hdr->e_phoff + 0x400000 + i,
								sizeof(*p_hdr))))
			return (NULL);
		i += sizeof(*p_hdr);
	}
	if (p_hdr && p_hdr->p_type != type)
	{
		free(p_hdr);
		p_hdr = NULL;
	}
	return (p_hdr);
}

Elf64_Dyn				*leak_elf_dyn(void *param, t_leak_ft leak_data,
									  Elf64_Phdr *p_hdr, Elf64_Sxword type)
{
	Elf64_Dyn			*dyn;
	size_t				max;
	size_t				i;
	Elf64_Sxword		dtag;

	max = p_hdr->p_memsz / sizeof(Elf64_Dyn);
	i = 0;
	if (!(dyn = leak_data(param, p_hdr->p_vaddr + i * sizeof(Elf64_Dyn),
						  sizeof(Elf64_Dyn))))
		return (NULL);
	dtag = dyn->d_tag;
	while (dtag != type && i < max)
	{
		free(dyn);
		if (!(dyn = leak_data(param, p_hdr->p_vaddr + i * sizeof(Elf64_Dyn),
							  sizeof(Elf64_Dyn))))
			return (NULL);
		dtag = dyn->d_tag;
		++i;
	}
	if (dtag != type)
	{
		free(dyn);
		dyn = NULL;
	}
	return (dyn);

}

int						elf_valid_magic(u_char *magic)
{
	if (magic[EI_MAG0] != ELFMAG0)
		return (-1);
	if (magic[EI_MAG1] != ELFMAG1)
		return (-1);
	if (magic[EI_MAG2] != ELFMAG2)
		return (-1);
	if (magic[EI_MAG3] != ELFMAG3)
		return (-1);
	return (0);
}

int						elf_x64_valid(Elf64_Ehdr *e_hdr)
{
	if (elf_valid_magic(e_hdr->e_ident))
		return (-1);
	if (e_hdr->e_ident[EI_CLASS] != ELFCLASS64)
		return (-1);
	if (e_hdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return (-1);
	if (e_hdr->e_type != ET_EXEC)
		return (-1);
	return (0);
}


static struct link_map		*elf_linkmap_base(void *param, t_leak_ft leak_data,
											  Elf64_Dyn *got)
{
	long					*lm_addr;
	struct link_map			*link_map;

	link_map = NULL;
	/* link_map is second entry in GOT */
	lm_addr = leak_data(param, got->d_un.d_ptr + sizeof(long),
						sizeof(long));
	link_map = leak_data(param, *lm_addr, sizeof(*link_map));
	free(lm_addr);
	return (link_map);
}

struct link_map				*leak_elf_linkmap(void *param, t_leak_ft leak_data,
											  Elf64_Dyn *got)
{
	struct link_map			*link_map;
	struct link_map			*l;

	link_map = elf_linkmap_base(param, leak_data, got);
	l = link_map;
	while (link_map)
	{
		/*	link_map->l_name = get_str(param, (long)link_map->l_name); */
		if (link_map->l_next)
			link_map->l_next = leak_data(param, (long)link_map->l_next,
										 sizeof(*link_map));
		link_map = link_map->l_next;
	}
	return (l);
}

t_tables_addr				*leak_elf_tables(void *param, t_leak_ft leak_data,
											 struct link_map *link_map)
{
	t_tables_addr			*tables;
	Elf64_Dyn				*dyn;
	unsigned long			addr;

	if (!(tables = malloc(sizeof(*tables))))
		return (NULL);
	bzero(tables, sizeof(*tables));
	addr = (unsigned long)link_map->l_ld;
	if ((dyn = leak_data(param, addr, sizeof(*dyn))))
	{
		while (dyn->d_tag)
		{
			if (dyn->d_tag == DT_SYMTAB)
				tables->symtab = dyn->d_un.d_ptr;
			if (dyn->d_tag == DT_STRTAB)
				tables->strtab = dyn->d_un.d_ptr;
			if (dyn->d_tag == DT_HASH)
			{
				if ((tables->nchains
					 = leak_data(param, dyn->d_un.d_ptr + sizeof(Elf64_Word),
								 sizeof(Elf64_Word))))
					*tables->nchains = (Elf64_Word)*tables->nchains;
			}
			free(dyn);
			addr += sizeof(*dyn);
			if (!(dyn = leak_data(param, addr, sizeof(*dyn))))
				return (NULL);
		}
	}
	return (tables);
}

char							*leak_str(void *data, t_leak_ft leak_data,
										  long addr)
{
	char						*s;
	long						*word;
	size_t						i;

	s = NULL;
	i = 0;
	word = NULL;
	while (!word || !memchr(word, 0, sizeof(*word)))
	{
		if (!(s = realloc(s, i + sizeof(*word))))
			return (NULL);
		if (!(word = leak_data(data, addr + i, sizeof(*word))))
			return (NULL);
		strncpy(s + i, (const char *)word, sizeof(*word));
		i += sizeof(*word);
	}
	return (s);
}

Elf64_Addr				leak_elf_symbol_addr(void *param, t_leak_ft leak_data,
											 struct link_map *link_map,
											 t_tables_addr *tables, char *name)
{
	size_t				i;
	Elf64_Sym			*sym;
	long				ret;
	char				*s;

	i = 0;
	ret = 0;
	if (tables->nchains && !ret)
	{
		while (i < *tables->nchains)
		{
			if (!(sym = leak_data(param, tables->symtab + i * sizeof(*sym),
								  sizeof(*sym))))
				return (0);
			if ((s = leak_str(param, leak_data,
							  (long)tables->strtab + sym->st_name)))
			{
				if (!strcmp(name, s))
					ret = link_map->l_addr + sym->st_value;
			}
			free(sym);
			free(s);
			++i;
		}
	}
	return (ret);
}

Elf64_Addr					leak_elf_sym_addr(int pid, t_leak_ft leak_ft,
										  char *symname)
{
	Elf64_Ehdr				*e_hdr = NULL;
	Elf64_Phdr				*p_dyn = NULL;
	Elf64_Dyn				*d_got = NULL;
	struct link_map			*link_map = NULL;
	t_tables_addr			*tables = NULL;
	Elf64_Addr				addr;

	if (!(e_hdr = leak_elf_ehdr(&pid, leak_ft)))
		return (-1);
	if (!(p_dyn = leak_elf_phdr_entry(&pid, leak_ft, e_hdr, PT_DYNAMIC)))
		return (-1);
	if (!(d_got = leak_elf_dyn(&pid, leak_ft, p_dyn, DT_PLTGOT)))
		return (-1);
	if (!(link_map = leak_elf_linkmap(&pid, leak_ft, d_got)))
		return (-1);
	struct link_map *lm = link_map;
	addr = 0;
	while (lm && !addr)
	{
		if (tables || (tables = leak_elf_tables(&pid, leak_ft, lm))
			&& tables->nchains)
			addr = leak_elf_symbol_addr(&pid, leak_ft, lm, tables, symname);
		free(tables->nchains);
		free(tables);
		tables = NULL;
		lm = lm->l_next;
	}
	return (addr);
}
