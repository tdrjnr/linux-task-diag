#include <linux/kernel.h>
#include <linux/taskstats_kern.h>
#include <uapi/linux/task_diag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/taskstats.h>

static size_t taskdiag_packet_size(u64 show_flags)
{
	size_t size;

	size = nla_total_size(sizeof(pid_t));

	if (show_flags & TASK_DIAG_SHOW_MSG)
		size += nla_total_size(sizeof(struct task_diag_msg));

	if (show_flags & TASK_DIAG_SHOW_CRED)
		size += nla_total_size(sizeof(struct task_diag_creds));

	if (show_flags & TASK_DIAG_SHOW_STAT)
		size += nla_total_size(sizeof(struct taskstats));

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

static int fill_stats(struct task_struct *tsk, struct sk_buff *skb)
{
	struct taskstats *diag_stats;
	struct nlattr *attr;
	int ret;

	attr = nla_reserve(skb, TASK_DIAG_STAT, sizeof(struct taskstats));
	if (!attr)
		return -EMSGSIZE;

	diag_stats = nla_data(attr);

	ret = fill_stats_for_pid(task_pid_vnr(tsk), diag_stats);
	if (ret)
		return ret;
	return 0;
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

static u64 get_vma_flags(struct vm_area_struct *vma)
{
	u64 flags = 0;
#define VM_TO_DIAG(flag) [ilog2(VM_##flag)] = TASK_DIAG_VMA_F_##flag,

	static const u64 mnemonics[BITS_PER_LONG] = {
		/*
		 * In case if we meet a flag we don't know about.
		 */
		[0 ... (BITS_PER_LONG-1)] = 0,

		VM_TO_DIAG(READ)
		VM_TO_DIAG(WRITE)
		VM_TO_DIAG(EXEC)
		VM_TO_DIAG(SHARED)
		VM_TO_DIAG(MAYREAD)
		VM_TO_DIAG(MAYWRITE)
		VM_TO_DIAG(MAYEXEC)
		VM_TO_DIAG(MAYSHARE)
		VM_TO_DIAG(GROWSDOWN)
		VM_TO_DIAG(PFNMAP)
		VM_TO_DIAG(DENYWRITE)
#ifdef CONFIG_X86_INTEL_MPX
		VM_TO_DIAG(MPX)
#endif
		VM_TO_DIAG(LOCKED)
		VM_TO_DIAG(IO)
		VM_TO_DIAG(SEQ_READ)
		VM_TO_DIAG(RAND_READ)
		VM_TO_DIAG(DONTCOPY)
		VM_TO_DIAG(DONTEXPAND)
		VM_TO_DIAG(ACCOUNT)
		VM_TO_DIAG(NORESERVE)
		VM_TO_DIAG(HUGETLB)
		VM_TO_DIAG(ARCH_1)
		VM_TO_DIAG(DONTDUMP)
#ifdef CONFIG_MEM_SOFT_DIRTY
		VM_TO_DIAG(SOFTDIRTY)
#endif
		VM_TO_DIAG(MIXEDMAP)
		VM_TO_DIAG(HUGEPAGE)
		VM_TO_DIAG(NOHUGEPAGE)
		VM_TO_DIAG(MERGEABLE)
	};
	size_t i;

	for (i = 0; i < BITS_PER_LONG; i++) {
		if (vma->vm_flags & (1UL << i))
			flags |= mnemonics[i];
	}

	return flags;
}

static int fill_vma(struct task_struct *p, struct sk_buff *skb, struct netlink_callback *cb, bool *progress)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct nlattr *attr;
	unsigned long mark = 0;
	char *page;
	int i, rc;

	if (cb)
		mark = cb->args[2];

	mm = p->mm;
	if (!mm || !atomic_inc_not_zero(&mm->mm_users))
		return 0;

	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page) {
		mmput(mm);
		return -ENOMEM;
	}

	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next, i++) {
		struct task_diag_vma diag_vma;
		unsigned char *b = skb_tail_pointer(skb);
		unsigned long start, end;
		const char *name = NULL;

		if (mark > vma->vm_start)
			continue;

		mark = vma->vm_start;

		attr = nla_reserve(skb, TASK_DIAG_VMA, sizeof(diag_vma));
		if (!attr) {
			rc = -EMSGSIZE;
			goto err;
		}

		/* We don't show the stack guard page in /proc/maps */
		start = vma->vm_start;
		if (stack_guard_page_start(vma, start))
			start += PAGE_SIZE;
		end = vma->vm_end;
		if (stack_guard_page_end(vma, end))
			end -= PAGE_SIZE;

		diag_vma.start    = start;
		diag_vma.end      = end;
		diag_vma.vm_flags = get_vma_flags(vma);
		diag_vma.pgoff    = 0;

		if (vma->vm_file) {
			struct inode *inode = file_inode(vma->vm_file);
			dev_t dev;

			dev = inode->i_sb->s_dev;
			diag_vma.major = MAJOR(dev);
			diag_vma.minor = MINOR(dev);
			diag_vma.inode = inode->i_ino;
			diag_vma.pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
		} else {
			diag_vma.major = 0;
			diag_vma.minor = 0;
			diag_vma.inode = 0;
			diag_vma.pgoff = 0;
		}

		memcpy(nla_data(attr), &diag_vma, sizeof(diag_vma));
		if (vma->vm_file) {
			char *p;

			p = d_path(&vma->vm_file->f_path, page, PAGE_SIZE);
			if (IS_ERR(p)) {
				nlmsg_trim(skb, b);
				rc = PTR_ERR(p);
				goto err;
			}
			name = p;
			goto done;
		}

		if (vma->vm_ops && vma->vm_ops->name) {
			name = vma->vm_ops->name(vma);
			if (name)
				goto done;
		}

		name = arch_vma_name(vma);
done:
		if (name) {
			int len;

			len = strlen(name) + 1;
			attr = nla_reserve(skb, TASK_DIAG_VMA_NAME, len);
			if (!attr) {
				nlmsg_trim(skb, b);
				rc = -EMSGSIZE;
				goto err;
			}

			memcpy(nla_data(attr), name, len);
		}
		*progress = true;
	}

	up_read(&mm->mmap_sem);
	mmput(mm);
	free_page((unsigned long) page);
	if (cb)
		cb->args[2] = 0;
	return 0;

err:
	up_read(&mm->mmap_sem);
	mmput(mm);
	free_page((unsigned long) page);
	if (cb)
		cb->args[2] = mark;

	return rc;
}

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
				u64 show_flags, u32 portid, u32 seq,
				struct netlink_callback *cb)
{
	void *reply;
	int err = 0, i = 0, n = 0;
	bool progress = false;
	pid_t pid;

	if (cb)
		n = cb->args[1];

	reply = genlmsg_put(skb, portid, seq, &taskstats_family, 0, TASK_DIAG_CMD_GET);
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

	if (show_flags & TASK_DIAG_SHOW_CRED) {
		if (i >= n)
			err = fill_creds(tsk, skb);
		if (err)
			goto err;
		i++;
	}

	if (show_flags & TASK_DIAG_SHOW_STAT) {
		if (i >= n)
			err = fill_stats(tsk, skb);
		if (err)
			goto err;
		i++;
	}

	if (show_flags & TASK_DIAG_SHOW_VMA) {
		if (i >= n)
			err = fill_vma(tsk, skb, cb, &progress);
		if (err)
			goto err;
		i++;
	}

	genlmsg_end(skb, reply);
	if (cb)
		cb->args[1] = 0;

	return 0;
err:
	if (err == -EMSGSIZE && (i > n || progress)) {
		if (cb)
			cb->args[1] = i;
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

	switch (iter->req.dump_stratagy) {
	case TASK_DIAG_DUMP_ALL:
		task = iter->tgid.task;
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

	switch (iter->req.dump_stratagy) {
	case TASK_DIAG_DUMP_ONE:
		if (iter->parent == NULL)
			return ERR_PTR(-ESRCH);
		iter->pos = iter->cb->args[0];
		if (iter->pos == 0) {
			iter->task = iter->parent;
			get_task_struct(iter->task);
		} else
			iter->task = NULL;
		return iter->task;
	case TASK_DIAG_DUMP_THREAD:
		if (iter->parent == NULL)
			return ERR_PTR(-ESRCH);

		iter->pos = iter->cb->args[0];
		iter->task = task_first_tid(iter->parent, 0, iter->pos, iter->ns);
		return iter->task;

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
	switch (iter->req.dump_stratagy) {
	case TASK_DIAG_DUMP_ONE:
		iter->pos++;
		iter->cb->args[0] = iter->pos;
		if (iter->task)
			put_task_struct(iter->task);
		iter->task = NULL;
		return NULL;
	case TASK_DIAG_DUMP_THREAD:
		iter->pos++;
		iter->task = task_next_tid(iter->task);
		iter->cb->args[0] = iter->pos;
		return iter->task;
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
	struct task_struct *tsk = NULL;
	struct task_diag_pid *preq, req;
	struct sk_buff *msg = NULL;
	size_t size;
	int rc;

	preq = nla_data(info->attrs[TASK_DIAG_CMD_ATTR_GET]);
	if (preq == NULL)
		return -EINVAL;

	if (nla_len(info->attrs[TASK_DIAG_CMD_ATTR_GET]) < sizeof(req))
		return -EINVAL;

	memcpy(&req, preq, sizeof(req));

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
