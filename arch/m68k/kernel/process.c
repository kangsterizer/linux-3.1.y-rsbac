#ifdef CONFIG_MMU
#include "process_mm.c"
#else
#include "process_no.c"
#endif
#ifdef CONFIG_RSBAC
	register long clone_arg __asm__ ("d1") = flags | CLONE_VM | CLONE_UNTRACED | CLONE_KTHREAD;
#else
#endif

#ifdef CONFIG_RSBAC
	if (pid > 0)
		rsbac_kthread_notify(find_pid_ns(pid, &init_pid_ns));
#endif

