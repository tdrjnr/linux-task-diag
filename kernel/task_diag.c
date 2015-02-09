#include <linux/kernel.h>
#include <linux/taskstats_kern.h>
#include <linux/task_diag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <net/sock.h>

struct task_diag_cb {
	int	attr;
};

static size_t taskdiag_packet_size(u64 show_flags)
{
	size_t size;

	size = nla_total_size(sizeof(u32)); /* PID */

	if (show_flags & TASK_DIAG_SHOW_BASE)
		size += nla_total_size(sizeof(struct task_diag_base));

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

static int fill_task_base(struct task_struct *p, struct sk_buff *skb, struct pid_namespace *ns)
{
	struct task_diag_base *base;
	struct nlattr *attr;
	char tcomm[sizeof(p->comm)];
	struct task_struct *tracer;

	attr = nla_reserve(skb, TASK_DIAG_BASE, sizeof(struct task_diag_base));
	if (!attr)
		return -EMSGSIZE;

	base = nla_data(attr);

	rcu_read_lock();
	base->ppid = pid_alive(p) ?
		task_tgid_nr_ns(rcu_dereference(p->real_parent), ns) : 0;

	base->tpid = 0;
	tracer = ptrace_parent(p);
	if (tracer)
		base->tpid = task_pid_nr_ns(tracer, ns);

	base->tgid = task_tgid_nr_ns(p, ns);
	base->pid = task_pid_nr_ns(p, ns);
	base->sid = task_session_nr_ns(p, ns);
	base->pgid = task_pgrp_nr_ns(p, ns);

	rcu_read_unlock();

	get_task_comm(tcomm, p);
	memset(base->comm, 0, TASK_DIAG_COMM_LEN);
	strncpy(base->comm, tcomm, TASK_DIAG_COMM_LEN);

	base->state = get_task_state(p);

	return 0;
}

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
				u64 show_flags, u32 portid, u32 seq,
				struct task_diag_cb *cb, struct pid_namespace *pidns)
{
	void *reply;
	int err = 0, i = 0, n = 0;
	int flags = 0;
	u32 pid;

	if (cb) {
		n = cb->attr;
		flags |= NLM_F_MULTI;
	}

	reply = genlmsg_put(skb, portid, seq, &taskstats_family,
					flags, TASK_DIAG_CMD_GET);
	if (reply == NULL)
		return -EMSGSIZE;

	pid = task_pid_nr_ns(tsk, pidns);
	err = nla_put_u32(skb, TASK_DIAG_PID, pid);
	if (err)
		goto err;

	if (show_flags & TASK_DIAG_SHOW_BASE) {
		if (i >= n)
			err = fill_task_base(tsk, skb, pidns);
		if (err)
			goto err;
		i++;
	}

	genlmsg_end(skb, reply);
	if (cb)
		cb->attr = 0;

	return 0;
err:
	if (err == -EMSGSIZE && i != 0) {
		if (cb)
			cb->attr = i;
		genlmsg_end(skb, reply);
	} else
		genlmsg_cancel(skb, reply);

	return err;
}

static bool task_diag_may_access(struct sk_buff *skb, struct task_struct *tsk)
{
	const struct cred *cred = NETLINK_CB(skb).sk->sk_socket->file->f_cred;

	return !ptrace_cred_may_access(cred, tsk, PTRACE_MODE_READ);
}

int taskdiag_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct task_diag_cb *diag_cb = (struct task_diag_cb *) cb->args;
	struct pid_namespace *pidns;
	struct tgid_iter iter;
	struct nlattr *na;
	struct task_diag_pid req;
	int rc;

	BUILD_BUG_ON(sizeof(struct task_diag_cb) > sizeof(cb->args));

	if (NETLINK_CB(cb->skb).pid == NULL)
		return -EINVAL;

	if (nlmsg_len(cb->nlh) < GENL_HDRLEN + sizeof(req))
		return -EINVAL;

	if (NETLINK_CB(cb->skb).pid == NULL)
		return -EINVAL;

	na = nlmsg_data(cb->nlh) + GENL_HDRLEN;
	if (na->nla_type < 0)
		return -EINVAL;

	pidns  = ns_of_pid(NETLINK_CB(cb->skb).pid);

	memcpy(&req, nla_data(na), sizeof(req));

	iter.tgid = cb->args[0];
	iter.task = NULL;
	for (iter = next_tgid(pidns, iter);
	     iter.task;
	     iter.tgid += 1, iter = next_tgid(pidns, iter)) {
		if (!task_diag_may_access(cb->skb, iter.task))
			continue;

		rc = task_diag_fill(iter.task, skb, req.show_flags,
				NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
				diag_cb, pidns);
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

int taskdiag_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *nla = info->attrs[TASK_DIAG_CMD_ATTR_GET];
	struct pid_namespace *pidns;
	struct task_struct *tsk = NULL;
	struct task_diag_pid req;
	struct sk_buff *msg = NULL;
	size_t size;
	int rc;

	if (NETLINK_CB(skb).pid == NULL)
		return -EINVAL;

	if (!nla_data(nla))
		return -EINVAL;

	if (nla_len(nla) < sizeof(req))
		return -EINVAL;

	/*
	 * use a req variable to deal with alignment issues. task_diag_pid
	 * contains u64 elements which means extended load operations can be
	 * used and those can require 8-byte alignment (e.g., sparc)
	 */
	memcpy(&req, nla_data(nla), sizeof(req));

	rcu_read_lock();
	tsk = find_task_by_vpid(req.pid);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	if (!tsk)
		return -ESRCH;

	if (!task_diag_may_access(skb, tsk)) {
		put_task_struct(tsk);
		return -EPERM;
	}

	pidns  = ns_of_pid(NETLINK_CB(skb).pid);

	size = taskdiag_packet_size(req.show_flags);

	while (1) {
		msg = genlmsg_new(size, GFP_KERNEL);
		if (!msg) {
			put_task_struct(tsk);
			return -EMSGSIZE;
		}

		rc = task_diag_fill(tsk, msg, req.show_flags,
					info->snd_portid, info->snd_seq, NULL,
					pidns);
		if (rc != -EMSGSIZE)
			break;

		nlmsg_free(msg);
		size += 128;
	}

	put_task_struct(tsk);
	if (rc < 0) {
		nlmsg_free(msg);
		return rc;
	}

	return genlmsg_reply(msg, info);
}
