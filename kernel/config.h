#ifndef _CONFIG_H_
#define _CONFIG_H_

// we use only one HART (cpu) in fundamental experiments
#define NCPU 1

//interval of timer interrupt. added @lab1_3
#define TIMER_INTERVAL 1000000

// the maximum memory space that PKE is allowed to manage. added @lab2_1
#define PKE_MAX_ALLOWABLE_RAM 128 * 1024 * 1024

<<<<<<< HEAD
// the ending physical address that PKE observes. added @lab2_1
#define PHYS_TOP (DRAM_BASE + PKE_MAX_ALLOWABLE_RAM)
=======
/* we use fixed physical (also logical) addresses for the stacks and trap frames as in
 Bare memory-mapping mode */
 //这里规定了几个栈的地址 当Bare memory-mapping mode的时候
// user stack top
#define USER_STACK 0x81100000

// the stack used by PKE kernel when a syscall happens
#define USER_KSTACK 0x81200000

// the trap frame used to assemble the user "process"
#define USER_TRAP_FRAME 0x81300000
>>>>>>> lab1_3_irq

#endif
