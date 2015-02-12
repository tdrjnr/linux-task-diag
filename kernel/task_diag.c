#include <linux/kernel.h>
#include <linux/taskstats_kern.h>
#include <linux/task_diag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>

static size_t taskdiag_packet_size(u64 show_flags)
{
	size_t size;

	size = nla_total_size(sizeof(u32)); /* PID */

	if (show_flags & TASK_DIAG_SHOW_BASE)
		size += nla_total_size(sizeof(struct task_diag_base));

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

static int fill_task_base(struct task_struct *p, struct sk_buff *skb)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
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

	put_cred(cred);

	return 0;
}

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
				u64 show_flags, u32 portid, u32 seq,
				struct netlink_callback *cb)
{
	void *reply;
	int err = 0, i = 0, n = 0;
	int flags = 0;
	u32 pid;

	if (cb) {
		n = cb->args[2];
		flags |= NLM_F_MULTI;
	}

	reply = genlmsg_put(skb, portid, seq, &taskstats_family,
					flags, TASK_DIAG_CMD_GET);
	if (reply == NULL)
		return -EMSGSIZE;

	pid = task_pid_vnr(tsk);
	err = nla_put_u32(skb, TASK_DIAG_PID, pid);
	if (err)
		goto err;

	if (show_flags & TASK_DIAG_SHOW_BASE) {
		if (i >= n)
			err = fill_task_base(tsk, skb);
		if (err)
			goto err;
		i++;
	}

	if (show_flags & TASK_DIAG_SHOW_CRED) {
		if (i >= n)
			err = fill_creds(tsk, skb);
		if (err)
			goto err;
		i++;
	}

	genlmsg_end(skb, reply);
	if (cb)
		cb->args[2] = 0;

	return 0;
err:
	if (err == -EMSGSIZE && i != 0) {
		if (cb)
			cb->args[2] = i;
		genlmsg_end(skb, reply);
	} else
		genlmsg_cancel(skb, reply);

	return err;
}

struct task_iter {
	struct task_diag_pid req;
	struct pid_namespace *ns;
	struct netlink_callback *cb;
	struct task_struct *parent;

	union {
		struct tgid_iter tgid;
		struct {
			unsigned int		pos;
			struct task_struct	*task;
		};
	};
};

static void iter_stop(struct task_iter *iter)
{
	struct task_struct *task;

	if (iter->parent)
		put_task_struct(iter->parent);

	switch (iter->req.dump_strategy) {
	case TASK_DIAG_DUMP_ALL:
		task = iter->tgid.task;
		break;
	default:
		task = iter->task;
	}
	if (task)
		put_task_struct(task);
}

static struct task_struct *iter_start(struct task_iter *iter)
{
	if (iter->req.pid > 0) {
		rcu_read_lock();
		iter->parent = find_task_by_pid_ns(iter->req.pid, iter->ns);
		if (iter->parent)
			get_task_struct(iter->parent);
		rcu_read_unlock();
	}

	switch (iter->req.dump_strategy) {
	case TASK_DIAG_DUMP_CHILDREN:

		if (iter->parent == NULL)
			return ERR_PTR(-ESRCH);

		iter->pos = iter->cb->args[0];
		iter->task = task_next_child(iter->parent, NULL, iter->pos);
		return iter->task;

	case TASK_DIAG_DUMP_ALL:
		iter->tgid.tgid = iter->cb->args[0];
		iter->tgid.task = NULL;
		iter->tgid = next_tgid(iter->ns, iter->tgid);
		return iter->tgid.task;
	}

	return ERR_PTR(-EINVAL);
}

static struct task_struct *iter_next(struct task_iter *iter)
{
	switch (iter->req.dump_strategy) {
	case TASK_DIAG_DUMP_CHILDREN:
		iter->pos++;
		iter->task = task_next_child(iter->parent, iter->task, iter->pos);
		iter->cb->args[0] = iter->pos;
		return iter->task;

	case TASK_DIAG_DUMP_ALL:
		iter->tgid.tgid += 1;
		iter->tgid = next_tgid(iter->ns, iter->tgid);
		iter->cb->args[0] = iter->tgid.tgid;
		return iter->tgid.task;
	}

	return NULL;
}

int taskdiag_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct task_iter iter;
	struct nlattr *na;
	struct task_struct *task;
	int rc;

	if (nlmsg_len(cb->nlh) < GENL_HDRLEN + sizeof(iter.req))
		return -EINVAL;

	na = nlmsg_data(cb->nlh) + GENL_HDRLEN;
	if (na->nla_type < 0)
		return -EINVAL;

	memcpy(&iter.req, nla_data(na), sizeof(iter.req));

	iter.ns     = ns;
	iter.cb     = cb;
	iter.parent = NULL;

	task = iter_start(&iter);
	if (IS_ERR(task))
		return PTR_ERR(task);

	for (; task; task = iter_next(&iter)) {
		if (!ptrace_may_access(task, PTRACE_MODE_READ))
			continue;
		rc = task_diag_fill(task, skb, iter.req.show_flags,
				NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, cb);
		if (rc < 0) {
			if (rc != -EMSGSIZE) {
				iter_stop(&iter);
				return rc;
			}
			break;
		}
	}
	iter_stop(&iter);

	return skb->len;
}

int taskdiag_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *nla = info->attrs[TASK_DIAG_CMD_ATTR_GET];
	struct task_struct *tsk = NULL;
	struct task_diag_pid req;
	struct sk_buff *msg = NULL;
	size_t size;
	int rc;

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

	if (!ptrace_may_access(tsk, PTRACE_MODE_READ)) {
		put_task_struct(tsk);
		return -EPERM;
	}

	size = taskdiag_packet_size(req.show_flags);

	while (1) {
		msg = genlmsg_new(size, GFP_KERNEL);
		if (!msg) {
			put_task_struct(tsk);
			return -EMSGSIZE;
		}

		rc = task_diag_fill(tsk, msg, req.show_flags,
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
