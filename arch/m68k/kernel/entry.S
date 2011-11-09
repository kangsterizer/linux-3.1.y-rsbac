#ifdef CONFIG_MMU
#include "entry_mm.S"
#else
#include "entry_no.S"
#endif
#ifdef CONFIG_RSBAC
	/* we use 400, until sys_security gets defined here */
	.rept 399-343
		.long sys_ni_syscall
	.endr
	.long sys_rsbac
#endif
