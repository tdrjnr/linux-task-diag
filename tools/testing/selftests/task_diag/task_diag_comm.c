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

int quiet;

static struct nla_policy attr_policy[TASK_DIAG_ATTR_MAX + 1] = {
	[TASK_DIAG_PID] = { .type = NLA_U32},
	[TASK_DIAG_BASE] = { .minlen = sizeof(struct task_diag_base) },
	[TASK_DIAG_CRED] = { .minlen = sizeof(struct task_diag_creds) },
};

#define PSS_SHIFT 12
static int parse_cmd_new(struct nl_cache_ops *unused, struct genl_cmd *cmd,
			 struct genl_info *info, void *arg)
{
	struct nlattr **attrs;

	attrs = info->attrs;
	__u32 *last_pid = (__u32 *)arg, pid;

	if (arg) {
		pid = *((__u32 *)nla_data(attrs[TASK_DIAG_PID]));
#if 0
		if (pid != *last_pid)
			pr_info("Start getting information about %d\n", pid);
		else
			pr_info("Continue getting information about %d\n", pid);
#endif
		*last_pid = pid;
	}

	if (attrs[TASK_DIAG_BASE]) {
		struct task_diag_base *msg;

		/* For nested attributes, na follows */
		msg = nla_data(attrs[TASK_DIAG_BASE]);
		pr_info("pid %5d tgid %5d ppid %5d sid %5d pgid %5d comm %s\n",
			msg->pid, msg->tgid, msg->ppid, msg->sid, msg->pgid, msg->comm);
	}

	if (attrs[TASK_DIAG_CRED]) {
		struct task_diag_creds *creds;

		creds = nla_data(attrs[TASK_DIAG_CRED]);
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
		struct task_diag_vma *vma_tmp, vma;

		task_diag_for_each_vma(vma_tmp, attrs[TASK_DIAG_VMA]) {
			char *name;
			struct task_diag_vma_stat *stat_tmp, stat;

			name = task_diag_vma_name(vma_tmp);
			if (name == NULL)
				name = "";

			memcpy(&vma, vma_tmp, sizeof(vma));
			pr_info("%016llx-%016llx %016llx %s\n",
				vma.start, vma.end, vma.vm_flags, name);

			stat_tmp = task_diag_vma_stat(vma_tmp);
			if (stat_tmp)
				memcpy(&stat, stat_tmp, sizeof(stat));
			else
				memset(&stat, 0, sizeof(stat));

			pr_info(
				   "Size:           %8llu kB\n"
				   "Rss:            %8llu kB\n"
				   "Pss:            %8llu kB\n"
				   "Shared_Clean:   %8llu kB\n"
				   "Shared_Dirty:   %8llu kB\n"
				   "Private_Clean:  %8llu kB\n"
				   "Private_Dirty:  %8llu kB\n"
				   "Referenced:     %8llu kB\n"
				   "Anonymous:      %8llu kB\n"
				   "AnonHugePages:  %8llu kB\n"
				   "Swap:           %8llu kB\n",
				   (vma.end - vma.start) >> 10,
				   stat.resident >> 10,
				   (stat.pss >> (10 + PSS_SHIFT)),
				   stat.shared_clean  >> 10,
				   stat.shared_dirty  >> 10,
				   stat.private_clean >> 10,
				   stat.private_dirty >> 10,
				   stat.referenced >> 10,
				   stat.anonymous >> 10,
				   stat.anonymous_thp >> 10,
				   stat.swap >> 10);
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
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	if (hdr->nlmsg_type == NLMSG_DONE) {
		int *ret = nlmsg_data(hdr);

		if (*ret < 0) {
			pr_err("An error message is received: %s\n",
							strerror(-*ret));
			return *ret;
		}
		return 0;
	}

	return genl_handle_msg(msg, arg);
}
