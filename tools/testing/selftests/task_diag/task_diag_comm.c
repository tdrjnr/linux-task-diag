#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/cli/utils.h>

#include "task_diag.h"
#include "taskstats.h"
#include "task_diag_comm.h"

int quiet = 0;

static struct nla_policy attr_policy[TASK_DIAG_ATTR_MAX + 1] = {
	[TASK_DIAG_PID] = { .type = NLA_U32},
	[TASK_DIAG_BASE] = { .minlen = sizeof(struct task_diag_base) },
	[TASK_DIAG_CRED] = { .minlen = sizeof(struct task_diag_creds) },
};

static int parse_cmd_new(struct nl_cache_ops *unused, struct genl_cmd *cmd,
			 struct genl_info *info, void *arg)
{
	struct nlattr **attrs;
	attrs = info->attrs;

	pr_info("pid: %d\n", *((int *)nla_data(attrs[TASK_DIAG_PID])));

	if (attrs[TASK_DIAG_BASE]) {
		struct task_diag_base *msg;

		/* For nested attributes, na follows */
		msg = (struct task_diag_base *) nla_data(attrs[TASK_DIAG_BASE]);
		pr_info("pid %d ppid %d comm %s\n", msg->pid, msg->ppid, msg->comm);
	}

	if (attrs[TASK_DIAG_CRED]) {
		struct task_diag_creds *creds;

		creds = (struct task_diag_creds *) NLA_DATA(attrs[TASK_DIAG_CRED]);
		pr_info("uid: %d %d %d %d\n", creds->uid,
				creds->euid, creds->suid, creds->fsuid);
		pr_info("gid: %d %d %d %d\n", creds->uid,
				creds->euid, creds->suid, creds->fsuid);
		pr_info("CapInh: %08x%08x\n",
					creds->cap_inheritable.cap[1],
					creds->cap_inheritable.cap[0]);
		pr_info("CapPrm: %08x%08x\n",
					creds->cap_permitted.cap[1],
					creds->cap_permitted.cap[0]);
		pr_info("CapEff: %08x%08x\n",
					creds->cap_effective.cap[1],
					creds->cap_effective.cap[0]);
		pr_info("CapBnd: %08x%08x\n", creds->cap_bset.cap[1],
					creds->cap_bset.cap[0]);
	}

	if (attrs[TASK_DIAG_VMA]) {
		struct task_diag_vma *vma;

		task_diag_for_each_vma(vma, attrs[TASK_DIAG_VMA]) {
			char *name;
			name = task_diag_vma_name(vma);
			if (name == NULL)
				name = "";
			pr_info("%016llx-%016llx %016llx %s\n", vma->start, vma->end, vma->vm_flags, name);
		}
	}

	return 0;
}

static struct genl_cmd cmds[] = {
	{
		.c_id	   = TASK_DIAG_CMD_GET,
		.c_name	 = "taskstats_new()",
		.c_maxattr      = TASK_DIAG_ATTR_MAX,
		.c_attr_policy  = attr_policy,
		.c_msg_parser   = &parse_cmd_new,
	},
};

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

struct genl_ops ops = {
	.o_name = TASKSTATS_GENL_NAME,
	.o_cmds = cmds,
	.o_ncmds = ARRAY_SIZE(cmds),
};

int parse_cb(struct nl_msg *msg, void *arg)
{
	return genl_handle_msg(msg, NULL);
}
