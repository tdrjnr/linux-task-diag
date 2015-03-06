#include <linux/kernel.h>
#include <linux/taskstats_kern.h>
#include <uapi/linux/taskdiag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>

static size_t taskdiag_packet_size(u64 show_flags)
{
	size_t size;

	size = nla_total_size(sizeof(pid_t));

	if (show_flags & TASK_DIAG_SHOW_MSG)
		size += nla_total_size(sizeof(struct task_diag_msg));

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

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
				u64 show_flags, u32 portid, u32 seq,
				struct netlink_callback *cb)
{
	void *reply;
	int err = 0, i = 0, n = 0;
	pid_t pid;

	if (cb)
		n = cb->args[1];

	reply = genlmsg_put(skb, portid, seq, &taskstats_family, 0, TASKDIAG_CMD_GET);
	if (reply == NULL)
		return -EMSGSIZE;

	pid = task_pid_vnr(tsk);
	err = nla_put(skb, TASK_DIAG_PID, sizeof(pid), &pid);
	if (err)
		goto err;

	if (show_flags & TASK_DIAG_SHOW_MSG) {
		if (i >= n)
			err = fill_task_msg(tsk, skb);
		if (err)
			goto err;
		i++;
	}

	genlmsg_end(skb, reply);
	if (cb)
		cb->args[1] = 0;

	return 0;
err:
	if (err == -EMSGSIZE && i != 0) {
		if (cb)
			cb->args[1] = i;
		genlmsg_end(skb, reply);
	} else
		genlmsg_cancel(skb, reply);

	return err;
}

int taskdiag_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
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
				NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, cb);
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
	struct task_struct *tsk = NULL;
	struct task_diag_pid *req;
	struct sk_buff *msg = NULL;
	size_t size;
	int rc;

	req = nla_data(info->attrs[TASKDIAG_CMD_ATTR_GET]);
	if (req == NULL)
		return -EINVAL;

	if (nla_len(info->attrs[TASKDIAG_CMD_ATTR_GET]) < sizeof(*req))
		return -EINVAL;

	rcu_read_lock();
	tsk = find_task_by_vpid(req->pid);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	if (!tsk)
		return -ESRCH;

	if (!ptrace_may_access(tsk, PTRACE_MODE_READ)) {
		put_task_struct(tsk);
		return -EPERM;
	}

	size = taskdiag_packet_size(req->show_flags);

	while (1) {
		msg = genlmsg_new(size, GFP_KERNEL);
		if (!msg) {
			put_task_struct(tsk);
			return -EMSGSIZE;
		}

		rc = task_diag_fill(tsk, msg, req->show_flags,
					info->snd_portid, info->snd_seq, NULL);
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
