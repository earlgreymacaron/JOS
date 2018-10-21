// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/dwarf.h>
#include <kern/kdebug.h>
#include <kern/dwarf_api.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	        // enough for one VGA text line
#define TRAP_FLAG   (1 << 8)    // Trap flag in EFLAGS

struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
  { "backtrace", "Display series of currently active function calls", mon_backtrace },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

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
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    uint64_t rip,rbp,ret_addr;
    struct Ripdebuginfo info;
    int i, offset;
    int64_t CFA,arg_addr,arg;

    cprintf("Stack backtrace:\n");
    read_rip(rip);
    rbp = read_rbp();
    while (rbp != 0x0) {
      cprintf("  rbp %016x  rip %016x\n",rbp, rip);
      debuginfo_rip(rip, &info);
      cprintf("       %s:%d: %s+%016x  args:%d",
              info.rip_file,info.rip_line,info.rip_fn_name,rip - info.rip_fn_addr,info.rip_fn_narg);

      //The rule to calculate CFA is in reg_table's cfa_rule: 
      //cprintf("dw_regnum=%d, dw_offset=%d\n",info.reg_table.cfa_rule.dw_regnum, info.reg_table.cfa_rule.dw_offset);
      CFA = rbp + 16;

      for (i = 0; i < info.rip_fn_narg; i++) {
        arg_addr = CFA + info.offset_fn_arg[i];
        memcpy(&arg, (void *) arg_addr, info.size_fn_arg[i]);
        cprintf("   %016x", arg);
        //cprintf("\n %dth arg (%d) at %016x which is %016x from CFA",i, info.size_fn_arg[i], arg_addr, info.offset_fn_arg[i]);
      }
      cprintf("\n");

      //Set rip and rbp to the ones of previous(callee) stack 
      rip = *(uint64_t *)(rbp + 8);
      rbp = *(uint64_t *)rbp;
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
monitor(struct Trapframe *tf, bool is_brkpt)
{
	char *buf;
  uintptr_t rip;
  size_t trapno;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

  if (tf != NULL)
    print_trapframe(tf);

  // If monitor was invoked by breakpoint exception,
  // 'continue' execution from the current location
  if(is_brkpt) {

	  //cprintf("\nWelcome to the JOS_GDB monitor!\n");
    cprintf("Breakpoint exception at 0x%lx\n",tf->tf_rip);
    cprintf("ni -  Single-step execution\n");
    cprintf("c -  Contintue execution\n");


    // GDB mode due to breakpoint exception
    while(1) {

      buf = readline("K(GDB)> ");

      if (strcmp(buf,"ni") == 0) {
        cprintf("Single-step execution\n");

        // Set trap flag
        tf->tf_eflags |= TRAP_FLAG;
        //tf->tf_trapno = T_BRKPT;

        // Continue execution
        rip = tf->tf_rip;
        //cprintf("rip=0x%lx\n",rip);
        asm volatile("jmp *%0" : : "r" (rip));

        if (tf != NULL)
          print_trapframe(tf);

      } else if (strcmp(buf, "c") == 0) {
        // Continue execution
        cprintf("Continue execution\n");
        break;

      } else {
        cprintf("%s: undefined instruction\n",buf);
      }
    }
  }

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
