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
		"\tSTART <= END and they should both be in HEX form (without 0x prefix).";
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
