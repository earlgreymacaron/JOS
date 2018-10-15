/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <kern/macro.h>



###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushq $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushq $0;							\
	pushq $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
   Find the PUSHA,POPA macros in kern/macro.h. Since amd64 doesn't support
   pusha,popa so you will find these macros handy.
 */
TRAPHANDLER_NOEC(x_divide,0);
TRAPHANDLER_NOEC(x_debug,1);
TRAPHANDLER_NOEC(x_nmi,2);
TRAPHANDLER_NOEC(x_brkpt,3);
TRAPHANDLER_NOEC(x_oflow,4);
TRAPHANDLER_NOEC(x_bound,5);
TRAPHANDLER_NOEC(x_illop,6);
TRAPHANDLER_NOEC(x_device,7);
TRAPHANDLER(x_dbflt,8);
TRAPHANDLER_NOEC(x_coproc,9);
TRAPHANDLER(x_tss,10);
TRAPHANDLER(x_segnp,11);
TRAPHANDLER(x_stack,12);
TRAPHANDLER(x_gpflt,13);
TRAPHANDLER(x_pgflt,14);
TRAPHANDLER_NOEC(x_res,15);
TRAPHANDLER_NOEC(x_fperr,16);
TRAPHANDLER(x_align,17);
TRAPHANDLER_NOEC(x_mchk,18);
TRAPHANDLER_NOEC(x_simderr,19);
TRAPHANDLER_NOEC(x_syscall,48);
TRAPHANDLER_NOEC(x_default,500);



/*
 * Lab 3: Your code here for _alltraps
 *
 * Hint: Be sure to review the x64 calling convention from lab1
 *       for how to pass a pointer to the trapframe.
 */
_alltraps:
  sub     $0x10, %rsp
  movw    %ds,8(%rsp)
  movw    %es,(%rsp)
  PUSHA
  xorq    %rax, %rax
  movw    $GD_KD, %rax
  movw    %rax, %es
  movw    %rax, %ds
  movq    %rsp ,%rdi
  call trap
  POPA_
  movw    (%rsp),%es
  movw    8(%rsp),%ds
  add     $0x10, %rsp
  ret

