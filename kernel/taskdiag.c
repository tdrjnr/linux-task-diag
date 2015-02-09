#include <uapi/linux/taskdiag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>

static struct genl_family family = {
	.id		= GENL_ID_GENERATE,
	.name		= TASKDIAG_GENL_NAME,
	.version	= TASKDIAG_GENL_VERSION,
	.maxattr	= TASKDIAG_CMD_ATTR_MAX,
	.netnsok	= true,
};

static size_t taskdiag_packet_size(u64 show_flags)
{
	size_t size;

	size = nla_total_size(sizeof(struct task_diag_msg));

	if (show_flags & TASK_DIAG_SHOW_CRED)
		size += nla_total_size(sizeof(struct task_diag_creds));

	return size;
}

/*
 * The task state array is a strange "bitmap" of
 * reasons to sleep. Thus "running" is zero, and
 * you can test for combinations of others with
 * simple bit tests.
 */
static const __u8 task_state_array[] = {
	TASK_DIAG_RUNNING,
	TASK_DIAG_INTERRUPTIBLE,
	TASK_DIAG_UNINTERRUPTIBLE,
	TASK_DIAG_STOPPED,
	TASK_DIAG_TRACE_STOP,
	TASK_DIAG_DEAD,
	TASK_DIAG_ZOMBIE,
};

static inline const __u8 get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->state | tsk->exit_state) & TASK_REPORT;

	BUILD_BUG_ON(1 + ilog2(TASK_REPORT) != ARRAY_SIZE(task_state_array)-1);

	return task_state_array[fls(state)];
}

static int fill_task_msg(struct task_struct *p, struct sk_buff *skb)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct task_diag_msg *msg;
	struct nlattr *attr;
	char tcomm[sizeof(p->comm)];
	struct task_struct *tracer;

	attr = nla_reserve(skb, TASK_DIAG_MSG, sizeof(struct task_diag_msg));
	if (!attr)
		return -EMSGSIZE;

	msg = nla_data(attr);

	rcu_read_lock();
	msg->ppid = pid_alive(p) ?
		task_tgid_nr_ns(rcu_dereference(p->real_parent), ns) : 0;

	msg->tpid = 0;
	tracer = ptrace_parent(p);
	if (tracer)
		msg->tpid = task_pid_nr_ns(tracer, ns);

	msg->tgid = task_tgid_nr_ns(p, ns);
	msg->pid = task_pid_nr_ns(p, ns);
	msg->sid = task_session_nr_ns(p, ns);
	msg->pgid = task_pgrp_nr_ns(p, ns);

	rcu_read_unlock();

	get_task_comm(tcomm, p);
	memset(msg->comm, 0, TASK_DIAG_COMM_LEN);
	strncpy(msg->comm, tcomm, TASK_DIAG_COMM_LEN);

	msg->state = get_task_state(p);

	return 0;
}

static inline void caps2diag(struct task_diag_caps *diag, const kernel_cap_t *cap)
{
	int i;

	for (i = 0; i < _LINUX_CAPABILITY_U32S_3; i++)
		diag->cap[i] = cap->cap[i];
}

static int fill_creds(struct task_struct *p, struct sk_buff *skb)
{
	struct user_namespace *user_ns = current_user_ns();
	struct task_diag_creds *diag_cred;
	const struct cred *cred;
	struct nlattr *attr;

	attr = nla_reserve(skb, TASK_DIAG_CRED, sizeof(struct task_diag_creds));
	if (!attr)
		return -EMSGSIZE;

	diag_cred = nla_data(attr);

	cred = get_task_cred(p);

	caps2diag(&diag_cred->cap_inheritable, &cred->cap_inheritable);
	caps2diag(&diag_cred->cap_permitted, &cred->cap_permitted);
	caps2diag(&diag_cred->cap_effective, &cred->cap_effective);
	caps2diag(&diag_cred->cap_bset, &cred->cap_bset);

	diag_cred->uid   = from_kuid_munged(user_ns, cred->uid);
	diag_cred->euid  = from_kuid_munged(user_ns, cred->euid);
	diag_cred->suid  = from_kuid_munged(user_ns, cred->suid);
	diag_cred->fsuid = from_kuid_munged(user_ns, cred->fsuid);
	diag_cred->gid   = from_kgid_munged(user_ns, cred->gid);
	diag_cred->egid  = from_kgid_munged(user_ns, cred->egid);
	diag_cred->sgid  = from_kgid_munged(user_ns, cred->sgid);
	diag_cred->fsgid = from_kgid_munged(user_ns, cred->fsgid);

	return 0;
}

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
				u64 show_flags, u32 portid, u32 seq)
{
	void *reply;
	int err;

	reply = genlmsg_put(skb, portid, seq, &family, 0, TASKDIAG_CMD_GET);
	if (reply == NULL)
		return -EMSGSIZE;

	err = fill_task_msg(tsk, skb);
	if (err)
		goto err;

	if (show_flags & TASK_DIAG_SHOW_CRED) {
		err = fill_creds(tsk, skb);
		if (err)
			goto err;
	}

	return genlmsg_end(skb, reply);
err:
	genlmsg_cancel(skb, reply);
	return err;
}

static int taskdiag_dumpid(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct tgid_iter iter;
	struct nlattr *na;
	struct task_diag_pid *req;
	int rc;

	if (nlmsg_len(cb->nlh) < GENL_HDRLEN + sizeof(*req))
		return -EINVAL;

	na = nlmsg_data(cb->nlh) + GENL_HDRLEN;
	if (na->nla_type < 0)
		return -EINVAL;

	req = (struct task_diag_pid *) nla_data(na);

	iter.tgid = cb->args[0];
	iter.task = NULL;
	for (iter = next_tgid(ns, iter);
	     iter.task;
	     iter.tgid += 1, iter = next_tgid(ns, iter)) {
		if (!ptrace_may_access(iter.task, PTRACE_MODE_READ))
			continue;

		rc = task_diag_fill(iter.task, skb, req->show_flags,
				NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq);
		if (rc < 0) {
			put_task_struct(iter.task);
			if (rc != -EMSGSIZE)
				return rc;
			break;
		}
	}

	cb->args[0] = iter.tgid;

	return skb->len;
}

static int taskdiag_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct task_struct *tsk = NULL;
	struct task_diag_pid *req;
	struct sk_buff *msg;
	size_t size;
	int rc;

	req = nla_data(info->attrs[TASKDIAG_CMD_ATTR_GET]);
	if (req == NULL)
		return -EINVAL;

	if (nla_len(info->attrs[TASKDIAG_CMD_ATTR_GET]) < sizeof(*req))
		return -EINVAL;

	size = taskdiag_packet_size(req->show_flags);
	msg = genlmsg_new(size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	rcu_read_lock();
	tsk = find_task_by_vpid(req->pid);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	if (!tsk) {
		rc = -ESRCH;
		goto err;
	};

	if (!ptrace_may_access(tsk, PTRACE_MODE_READ)) {
		put_task_struct(tsk);
		rc = -EPERM;
		goto err;
	}

	rc = task_diag_fill(tsk, msg, req->show_flags,
				info->snd_portid, info->snd_seq);
	put_task_struct(tsk);
	if (rc < 0)
		goto err;

	return genlmsg_reply(msg, info);
err:
	nlmsg_free(msg);
	return rc;
}

static const struct nla_policy
			taskstats_cmd_get_policy[TASKDIAG_CMD_ATTR_MAX+1] = {
	[TASKDIAG_CMD_ATTR_GET]  = {	.type = NLA_UNSPEC,
					.len = sizeof(struct task_diag_pid)
				},
};

static const struct genl_ops taskdiag_ops[] = {
	{
		.cmd		= TASKDIAG_CMD_GET,
		.doit		= taskdiag_doit,
		.dumpit		= taskdiag_dumpid,
		.policy		= taskstats_cmd_get_policy,
	},
};

static int __init taskdiag_init(void)
{
	int rc;

	rc = genl_register_family_with_ops(&family, taskdiag_ops);
	if (rc)
		return rc;

	return 0;
}

late_initcall(taskdiag_init);
