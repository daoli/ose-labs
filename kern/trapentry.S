/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>



###################################################################
# exceptions/interrupts
###################################################################

.data
	// An interrupt information table.
	// Ends with a entry with `address == 0x0`.
	// Three 32bit numbers for each entry:
	//	interrupt number
	//	interrupt handler function address
	//	interrupt DPL
	.global intr_table;
intr_table:
.text

#define TRAPHANDLER_INFO(num, addr, dpl)				\
.data;									\
trapinfo_ ## num: .int num, addr, dpl ;					\
.text;

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
#define TRAPHANDLER(name, num, dpl)					\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps;							\
	TRAPHANDLER_INFO(num, name, dpl) ;

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num, dpl)				\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps;                                                  \
	TRAPHANDLER_INFO(num, name, dpl) ;


.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
TRAPHANDLER_NOEC(trap_0, T_DIVIDE, 0)
TRAPHANDLER_NOEC(trap_1, T_DEBUG, 0)
TRAPHANDLER_NOEC(trap_2, T_NMI, 0)
TRAPHANDLER_NOEC(trap_3, T_BRKPT, 3)
TRAPHANDLER_NOEC(trap_4, T_OFLOW, 0)
TRAPHANDLER_NOEC(trap_5, T_BOUND, 0)
TRAPHANDLER_NOEC(trap_6, T_ILLOP, 0)
TRAPHANDLER_NOEC(trap_7, T_DEVICE, 0)
TRAPHANDLER(trap_8, T_DBLFLT, 0)
TRAPHANDLER(trap_10, T_TSS, 0)
TRAPHANDLER(trap_11, T_SEGNP, 0)
TRAPHANDLER(trap_12, T_STACK, 0)
TRAPHANDLER(trap_13, T_GPFLT, 0)
TRAPHANDLER(trap_14, T_PGFLT, 0)
TRAPHANDLER_NOEC(trap_16, T_FPERR, 0)
TRAPHANDLER(trap_17, T_ALIGN, 0)
TRAPHANDLER_NOEC(trap_18, T_MCHK, 0)
TRAPHANDLER_NOEC(trap_19, T_SIMDERR, 0)
TRAPHANDLER_NOEC(trap_48, T_SYSCALL, 3)
//A termination indicator of the interrupt information table
TRAPHANDLER_INFO(0xFFFF, 0x0, 0)

/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:
	pushl	%ds		//build trapframe
	pushl	%es
	pushal
	movw	$GD_KD,%ax	//switch to kernel data segment
	movw	%ax,%ds
	movw	%ax,%es
	pushl	%esp		//call trap()
	call	trap

