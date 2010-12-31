#include <bc/decl.h>
#include <bc/task.h>

UB_DECLARE_FUNC(int, ub_oom_lock(void))
UB_DECLARE_FUNC(struct user_beancounter *, ub_oom_select_worst(void))
UB_DECLARE_VOID_FUNC(ub_oom_mm_killed(struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_oom_unlock(void))
UB_DECLARE_VOID_FUNC(ub_out_of_memory(struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_oom_task_dead(struct task_struct *tsk))
UB_DECLARE_FUNC(int, ub_oom_task_skip(struct user_beancounter *ub,
			struct task_struct *tsk))

#ifdef CONFIG_BEANCOUNTERS
extern int oom_generation;
extern int oom_kill_counter;
#define ub_oom_start() do {						\
		current->task_bc.oom_generation = oom_generation;	\
	} while (0)
#define ub_oom_task_killed(p) do { 					\
		oom_kill_counter++;					\
		wake_up_process(p);					\
	} while (0)
#else
#define ub_oom_start()			do { } while (0)
#define ub_oom_task_killed(p)		do { } while (0)
#endif
