#ifndef _LINUX_TASK_DIAG_H
#define _LINUX_TASK_DIAG_H

#include <linux/types.h>
#include <linux/capability.h>

enum {
	/* optional attributes which can be specified in show_flags */
	TASK_DIAG_BASE	= 0,

	/* other attributes */
	TASK_DIAG_PID	= 64,	/* u32 */

	__TASK_DIAG_ATTR_MAX
#define TASK_DIAG_ATTR_MAX (__TASK_DIAG_ATTR_MAX - 1)
};

#define TASK_DIAG_SHOW_BASE	(1ULL << TASK_DIAG_BASE)

enum {
	TASK_DIAG_RUNNING,
	TASK_DIAG_INTERRUPTIBLE,
	TASK_DIAG_UNINTERRUPTIBLE,
	TASK_DIAG_STOPPED,
	TASK_DIAG_TRACE_STOP,
	TASK_DIAG_DEAD,
	TASK_DIAG_ZOMBIE,
};

#define TASK_DIAG_COMM_LEN 16

struct task_diag_base {
	__u32	tgid;
	__u32	pid;
	__u32	ppid;
	__u32	tpid;
	__u32	sid;
	__u32	pgid;
	__u8	state;
	char	comm[TASK_DIAG_COMM_LEN];
};

#define TASK_DIAG_DUMP_ALL	0

struct task_diag_pid {
	__u64	show_flags;
	__u64	dump_strategy;

	__u32	pid;
};

enum {
	TASK_DIAG_CMD_ATTR_UNSPEC = 0,
	TASK_DIAG_CMD_ATTR_GET,
	__TASK_DIAG_CMD_ATTR_MAX,
};

#define TASK_DIAG_CMD_ATTR_MAX (__TASK_DIAG_CMD_ATTR_MAX - 1)

#endif /* _LINUX_TASK_DIAG_H */
