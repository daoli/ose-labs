// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line

extern uint16_t vga_color_scheme;

struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display stack backtrace", mon_backtrace },
	{ "matrix", "Turn on/off matrix style", mon_matrix },
	{ "mem_showmappings", "Show virtual memory mappings", mon_mem_showmappings },
	{ "mem_dump", "dump memory", mon_mem_dump },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t eip, ebp = read_ebp();
	uint32_t *p;
	struct Eipdebuginfo info;

	cprintf("Stack backtrace:\n");
	while(ebp) {
		p = (uint32_t *) ebp;
		eip = *(p+1);
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n",
				ebp, eip, *(p+2), *(p+3), *(p+4), *(p+5), *(p+6));

		debuginfo_eip(eip, &info);
		cprintf("         %s:%d: %.*s+%d\n",
				info.eip_file,
				info.eip_line,
				info.eip_fn_namelen,
				info.eip_fn_name,
				eip-info.eip_fn_addr);
		ebp = *p;
	}

	return 0;
}

int
mon_matrix(int argc, char **argv, struct Trapframe *tf)
{
	char *err_str = "Command format: matrix on|off";
	char *ok_str = "You should already see the difference. :-)";
	if (argc != 2 || (strcmp(argv[1], "on") && strcmp(argv[1], "off"))) {
		// Command format wrong
		cprintf("%s\n", err_str);
		return 0;
	} else {
		if (strcmp(argv[1], "on") == 0) {
			vga_color_scheme = 0x0200;
		} else {
			vga_color_scheme = 0x0700;
		}
		cprintf("%s\n", ok_str);
		return 0;
	}
}

int
mon_mem_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	char *err_str = "Command format: mem_showmappings START END\n"
		"\tSTART <= END and they should both be in HEX form.";
	uint32_t start, end, i, tmp;
	char *ep_start, *ep_end;
	struct page_info info;

	// Input arguments check
	if (argc != 3) {
		cprintf("%s\n", err_str);
		return 0;
	}
	start = (uint32_t) strtol(argv[1], &ep_start, 16);
	end = (uint32_t) strtol(argv[2], &ep_end, 16);
	if ((ep_start - argv[1]) != strlen(argv[1])
	    || (ep_end - argv[2]) != strlen(argv[2])
	    || start > end) {
		cprintf("%s\n", err_str);
		return 0;
	}

	// Print results
	for (i = 0; i <= PGNUM(end) - PGNUM(start); i++) {
		tmp = (~PGOFF(start) & start) + i * PGSIZE;
		cprintf("VA: 0x%08x to 0x%08x\n", tmp, tmp - 1 + PGSIZE);
		pg_info(kern_pgdir, (void *)tmp, &info);
		if (info.pse) {
			cprintf("    PDE[%4d] P = %s | R/W = %s | S/U = %s | 0x%08x - 0x%08x\n",
				PDX(tmp),
				(info.pde & PTE_P) ? " ON" : "OFF",
				(info.pde & PTE_W) ? "W" : "R",
				(info.pde & PTE_U) ? "U" : "S",
				PTE_ADDR_PSE(info.pde),
				PTE_ADDR_PSE(info.pde) - 1 + PTSIZE);
			continue;
		}
		cprintf("    PDE[%4d], P = %s | R/W = %s | S/U = %s\n",
			PDX(tmp),
			(info.pde & PTE_P) ? " ON" : "OFF",
			(info.pde & PTE_W) ? "W" : "R",
			(info.pde & PTE_U) ? "U" : "S");
		if (!(info.pde & PTE_P)) {
			continue;
		}
		cprintf("    PTE[%4d], P = %s | R/W = %s | S/U = %s | 0x%08x - 0x%08x\n",
			PTX(tmp),
			(info.pte & PTE_P) ? " ON" : "OFF",
			(info.pte & PTE_W) ? "W" : "R",
			(info.pte & PTE_U) ? "U" : "S",
			PTE_ADDR(info.pte),
			PTE_ADDR(info.pte) - 1 + PGSIZE);
	}
	return 0;
}

#define MD_COL 16
#define MD_OFF(addr) (((uint32_t) (addr)) & (MD_COL-1))
#define MD_MASK(addr) (~MD_OFF(addr) & ((uint32_t) (addr)))

// A helper function for memory dumping, it prints dump of physical memory
// in range [start, end]. An index number is printed every 'MD_COL' numbers on
// the leftmost.
//
// 'start_va' the initial index of the 'start', which is used as a index
//            offset.
// NOTE: it may cause kernel panic if accessing out of physical memory.
static void
mem_dump_helper(physaddr_t start, physaddr_t end, uintptr_t start_va,
		int include_offset)
{
	uint64_t i;
	uintptr_t va_index = start_va;

	if (!include_offset) {
		i = start;
	} else {
		i = MD_MASK(start);
		va_index = MD_MASK(start_va);
	}

	for (; i <= end; i++, va_index++) {
		if (va_index % MD_COL == 0) {
			cprintf("%08x   ", va_index);
		}
		if (include_offset && i < start) {
			cprintf("   ");
		} else {
			cprintf("%02x ", *((uint8_t *)KADDR(i)));
		}
		if ((MD_OFF(va_index) + 1) % MD_COL == 0) {
			cprintf("\n");
		}
	}

}

int
mon_mem_dump(int argc, char **argv, struct Trapframe *tf)
{
	char *err_str = "Command format: mem_dump p|v START END\n"
		"\t p|v, physical address or virtual address\n"
		"\t START <= END and they should both be in HEX form.";

	uint32_t start, end;
	uint64_t i;
	char *ep_start, *ep_end;
	struct page_info info;

	// Input arguments check
	if (argc != 4
	    || (strcmp(argv[1], "p") != 0 && strcmp(argv[1], "v") != 0)) {
		cprintf("%s\n", err_str);
		return 0;
	}
	start = (uint32_t) strtol(argv[2], &ep_start, 16);
	end = (uint32_t) strtol(argv[3], &ep_end, 16);
	if ((ep_start - argv[2]) != strlen(argv[2])
	    || (ep_end - argv[3]) != strlen(argv[3])
	    || start > end) {
		cprintf("%s\n", err_str);
		return 0;
	}

	// Dump memory
	if (strcmp(argv[1], "p") == 0) {
		mem_dump_helper(start, end, start, 1);
		if (MD_OFF(end) != MD_COL-1) {
			cprintf("\n");
		}
	} else {
		physaddr_t pa_start, pa_end;
		int first = 1;
		for (i = start; i <= end; i++) {
			// print one page of virtual address at a time.
			// '[pa_start, pa_end]' holds physical address boundary of one round.
			pg_info(kern_pgdir, (void *) (uint32_t) i, &info);
			if (info.pse && (info.pde & PTE_P)) {
				pa_start = PTE_ADDR_PSE(info.pde) + PGOFF_PSE(i);
				pa_end = PTE_ADDR_PSE(info.pde) - 1 + PTSIZE;
			} else if (!info.pse && (info.pde & PTE_P)
				   && (info.pte & PTE_P)) {
				pa_start = PTE_ADDR(info.pte) + PGOFF(i);
				pa_end = PTE_ADDR(info.pte) -1 + PGSIZE;
			} else {
				cprintf("VA: %x has no valid physical address mapping.\n", i);
				return 0;
			}
			if (pa_end - pa_start > end - i) {
				pa_end = end - i + pa_start;
			}
			mem_dump_helper(pa_start, pa_end, i, first);
			first = 0;
			i += pa_end - pa_start;
		}
		if (MD_OFF(end) != MD_COL-1) {
			cprintf("\n");
		}
	}

	return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
