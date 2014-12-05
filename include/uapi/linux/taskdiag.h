#ifndef _LINUX_TASKDIAG_H
#define _LINUX_TASKDIAG_H

#include <linux/types.h>
#include <linux/capability.h>

enum {
	/* optional attributes which can be specified in show_flags */
	TASK_DIAG_MSG	= 0,

	/* other attributes */
	TASK_DIAG_PID	= 64,
};

#define TASK_DIAG_SHOW_MSG (1ULL << TASK_DIAG_MSG)

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

struct task_diag_msg {
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
	__u64	dump_stratagy;

	__u32	pid;
};

enum {
	TASKDIAG_CMD_ATTR_UNSPEC = 0,
	TASKDIAG_CMD_ATTR_GET,
	__TASKDIAG_CMD_ATTR_MAX,
};

#define TASKDIAG_CMD_ATTR_MAX (__TASKDIAG_CMD_ATTR_MAX - 1)

#endif /* _LINUX_TASKDIAG_H */
