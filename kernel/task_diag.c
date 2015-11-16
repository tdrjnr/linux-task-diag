#include <linux/kernel.h>
#include <linux/taskstats_kern.h>
#include <linux/task_diag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/taskstats.h>
#include <linux/syscalls.h>

struct task_diag_cb {
	pid_t			pid;
	int			pos;
	int			attr;
	int			pad1;

	union { /* per-attribute */
		struct {
			unsigned long mark;
		} vma;
		long pad[4];
	};
};

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

	static const u64 mnemonics[BITS_PER_LONG] = {
		/*
		 * In case if we meet a flag we don't know about.
		 */
		[0 ... (BITS_PER_LONG-1)] = 0,

		[ilog2(VM_READ)]	= TASK_DIAG_VMA_F_READ,
		[ilog2(VM_WRITE)]	= TASK_DIAG_VMA_F_WRITE,
		[ilog2(VM_EXEC)]	= TASK_DIAG_VMA_F_EXEC,
		[ilog2(VM_SHARED)]	= TASK_DIAG_VMA_F_SHARED,
		[ilog2(VM_MAYREAD)]	= TASK_DIAG_VMA_F_MAYREAD,
		[ilog2(VM_MAYWRITE)]	= TASK_DIAG_VMA_F_MAYWRITE,
		[ilog2(VM_MAYEXEC)]	= TASK_DIAG_VMA_F_MAYEXEC,
		[ilog2(VM_MAYSHARE)]	= TASK_DIAG_VMA_F_MAYSHARE,
		[ilog2(VM_GROWSDOWN)]	= TASK_DIAG_VMA_F_GROWSDOWN,
		[ilog2(VM_PFNMAP)]	= TASK_DIAG_VMA_F_PFNMAP,
		[ilog2(VM_DENYWRITE)]	= TASK_DIAG_VMA_F_DENYWRITE,
#ifdef CONFIG_X86_INTEL_MPX
		[ilog2(VM_MPX)]		= TASK_DIAG_VMA_F_MPX,
#endif
		[ilog2(VM_LOCKED)]	= TASK_DIAG_VMA_F_LOCKED,
		[ilog2(VM_IO)]		= TASK_DIAG_VMA_F_IO,
		[ilog2(VM_SEQ_READ)]	= TASK_DIAG_VMA_F_SEQ_READ,
		[ilog2(VM_RAND_READ)]	= TASK_DIAG_VMA_F_RAND_READ,
		[ilog2(VM_DONTCOPY)]	= TASK_DIAG_VMA_F_DONTCOPY,
		[ilog2(VM_DONTEXPAND)]	= TASK_DIAG_VMA_F_DONTEXPAND,
		[ilog2(VM_ACCOUNT)]	= TASK_DIAG_VMA_F_ACCOUNT,
		[ilog2(VM_NORESERVE)]	= TASK_DIAG_VMA_F_NORESERVE,
		[ilog2(VM_HUGETLB)]	= TASK_DIAG_VMA_F_HUGETLB,
		[ilog2(VM_ARCH_1)]	= TASK_DIAG_VMA_F_ARCH_1,
		[ilog2(VM_DONTDUMP)]	= TASK_DIAG_VMA_F_DONTDUMP,
#ifdef CONFIG_MEM_SOFT_DIRTY
		[ilog2(VM_SOFTDIRTY)]	= TASK_DIAG_VMA_F_SOFTDIRTY,
#endif
		[ilog2(VM_MIXEDMAP)]	= TASK_DIAG_VMA_F_MIXEDMAP,
		[ilog2(VM_HUGEPAGE)]	= TASK_DIAG_VMA_F_HUGEPAGE,
		[ilog2(VM_NOHUGEPAGE)]	= TASK_DIAG_VMA_F_NOHUGEPAGE,
		[ilog2(VM_MERGEABLE)]	= TASK_DIAG_VMA_F_MERGEABLE,
	};
	size_t i;

	for (i = 0; i < BITS_PER_LONG; i++) {
		if (vma->vm_flags & (1UL << i))
			flags |= mnemonics[i];
	}

	return flags;
}

/*
 * use a tmp variable and copy to input arg to deal with
 * alignment issues. diag_vma contains u64 elements which
 * means extended load operations can be used and those can
 * require 8-byte alignment (e.g., sparc)
 */
static void fill_diag_vma(struct vm_area_struct *vma,
			  struct task_diag_vma *diag_vma)
{
	struct task_diag_vma tmp;

	/* We don't show the stack guard page in /proc/maps */
	tmp.start = vma->vm_start;
	if (stack_guard_page_start(vma, tmp.start))
		tmp.start += PAGE_SIZE;

	tmp.end = vma->vm_end;
	if (stack_guard_page_end(vma, tmp.end))
		tmp.end -= PAGE_SIZE;
	tmp.vm_flags = get_vma_flags(vma);

	if (vma->vm_file) {
		struct inode *inode = file_inode(vma->vm_file);
		dev_t dev;

		dev = inode->i_sb->s_dev;
		tmp.major = MAJOR(dev);
		tmp.minor = MINOR(dev);
		tmp.inode = inode->i_ino;
		tmp.generation = inode->i_generation;
		tmp.pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	} else {
		tmp.major = 0;
		tmp.minor = 0;
		tmp.inode = 0;
		tmp.generation = 0;
		tmp.pgoff = 0;
	}

	memcpy(diag_vma, &tmp, sizeof(*diag_vma));
}

static const char *get_vma_name(struct vm_area_struct *vma, char *page)
{
	const char *name = NULL;

	if (vma->vm_file) {
		name = d_path(&vma->vm_file->f_path, page, PAGE_SIZE);
		goto out;
	}

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		if (name)
			goto out;
	}

	name = arch_vma_name(vma);

out:
	return name;
}

static void fill_diag_vma_stat(struct vm_area_struct *vma, struct task_diag_vma_stat *stat)
{
	struct task_diag_vma_stat tmp;
	struct mem_size_stats mss;
	struct mm_walk smaps_walk = {
		.pmd_entry = smaps_pte_range,
		.mm = vma->vm_mm,
		.private = &mss,
	};

	memset(&mss, 0, sizeof mss);
	memset(&tmp, 0, sizeof(tmp));

	/* mmap_sem is held in m_start */
	walk_page_vma(vma, &smaps_walk);

	tmp.resident		= mss.resident;
	tmp.pss			= mss.pss;
	tmp.shared_clean	= mss.shared_clean;
	tmp.private_clean	= mss.private_clean;
	tmp.private_dirty	= mss.private_dirty;
	tmp.referenced		= mss.referenced;
	tmp.anonymous		= mss.anonymous;
	tmp.anonymous_thp	= mss.anonymous_thp;
	tmp.swap		= mss.swap;

	memcpy(stat, &tmp, sizeof(*stat));
}

static int fill_vma(struct task_struct *p, struct sk_buff *skb,
		    struct task_diag_cb *cb, bool *progress, u64 show_flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct nlattr *attr = NULL;
	struct task_diag_vma *diag_vma;
	unsigned long mark = 0;
	char *page;
	int i, rc = -EMSGSIZE, size;

	if (cb)
		mark = cb->vma.mark;

	mm = p->mm;
	if (!mm || !atomic_inc_not_zero(&mm->mm_users))
		return 0;

	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page) {
		mmput(mm);
		return -ENOMEM;
	}

	size = NLA_ALIGN(sizeof(struct task_diag_vma));
	if (show_flags & TASK_DIAG_SHOW_VMA_STAT)
		size += NLA_ALIGN(sizeof(struct task_diag_vma_stat));

	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next, i++) {
		unsigned char *b = skb_tail_pointer(skb);
		const char *name;
		void *pfile;


		if (mark >= vma->vm_start)
			continue;

		/* setup pointer for next map */
		if (attr == NULL) {
			attr = nla_reserve(skb, TASK_DIAG_VMA, size);
			if (!attr)
				goto err;

			diag_vma = nla_data(attr);
		} else {
			diag_vma = nla_reserve_nohdr(skb, size);

			if (diag_vma == NULL) {
				nlmsg_trim(skb, b);
				goto out;
			}
		}

		fill_diag_vma(vma, diag_vma);

		if (show_flags & TASK_DIAG_SHOW_VMA_STAT) {
			struct task_diag_vma_stat *stat;

			stat = (void *) diag_vma + NLA_ALIGN(sizeof(struct task_diag_vma));

			fill_diag_vma_stat(vma, stat);
			diag_vma->stat_len = sizeof(struct task_diag_vma_stat);
			diag_vma->stat_off = (void *) stat - (void *)diag_vma;
		} else {
			diag_vma->stat_len = 0;
			diag_vma->stat_off = 0;
		}

		name = get_vma_name(vma, page);
		if (IS_ERR(name)) {
			nlmsg_trim(skb, b);
			rc = PTR_ERR(name);
			goto out;
		}

		if (name) {
			diag_vma->name_len = strlen(name) + 1;

			/* reserves NLA_ALIGN(len) */
			pfile = nla_reserve_nohdr(skb, diag_vma->name_len);
			if (pfile == NULL) {
				nlmsg_trim(skb, b);
				goto out;
			}
			diag_vma->name_off = pfile - (void *) diag_vma;
			memcpy(pfile, name, diag_vma->name_len);
		} else {
			diag_vma->name_len = 0;
			diag_vma->name_off = 0;
		}

		mark = vma->vm_start;

		diag_vma->vma_len = skb_tail_pointer(skb) - (unsigned char *) diag_vma;

		*progress = true;
	}

	rc = 0;
	mark = 0;
out:
	if (*progress)
		attr->nla_len = skb_tail_pointer(skb) - (unsigned char *) attr;

err:
	up_read(&mm->mmap_sem);
	mmput(mm);
	free_page((unsigned long) page);
	if (cb)
		cb->vma.mark = mark;

	return rc;
}

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
			  struct task_diag_pid *req, u32 portid, u32 seq,
			  struct task_diag_cb *cb)
{
	u64 show_flags = req->show_flags;
	struct pid_namespace *ns;
	void *reply;
	int err = 0, i = 0, n = 0;
	bool progress = false;
	int flags = 0;
	u32 pid, tgid;

	ns = task_active_pid_ns(current);

	reply = genlmsg_put(skb, portid, seq, &taskstats_family,
					flags, TASK_DIAG_CMD_GET);
	if (reply == NULL)
		return -EMSGSIZE;

	pid = task_pid_nr_ns(tsk, ns);
	err = nla_put_u32(skb, TASK_DIAG_PID, pid);
	if (err)
		goto err;

	tgid = task_tgid_nr_ns(tsk, ns);
	err = nla_put_u32(skb, TASK_DIAG_TGID, tgid);
	if (err)
		goto err;

	if (show_flags & TASK_DIAG_SHOW_BASE) {
		if (i >= n)
			err = fill_task_base(tsk, skb, ns);
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
		/* if the request is to dump all threads of all processes
		 * only show VMAs for group leader.
		 */
		if (req->dump_strategy == TASK_DIAG_DUMP_ALL_THREAD &&
		    !thread_group_leader(tsk))
			goto done;

		if (i >= n)
			err = fill_vma(tsk, skb, cb, &progress, show_flags);
		if (err)
			goto err;
		i++;
	}

done:
	genlmsg_end(skb, reply);
	if (cb)
		cb->attr = 0;

	return 0;
err:
	if (err == -EMSGSIZE && (i > n || progress)) {
		if (cb)
			cb->attr = i;
		genlmsg_end(skb, reply);
	} else
		genlmsg_cancel(skb, reply);

	return err;
}

struct task_iter {
	struct task_diag_pid req;
	struct task_diag_cb *cb;
	struct task_struct *parent;

	struct tgid_iter tgid;
	unsigned int		pos;
	struct task_struct	*task;
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
	case TASK_DIAG_DUMP_ALL_THREAD:
		/* release both tgid task and thread task */
		if (iter->task)
			put_task_struct(iter->task);
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
	struct pid_namespace *ns = task_active_pid_ns(current);

	if (iter->req.pid > 0) {
		rcu_read_lock();
		iter->parent = find_task_by_pid_ns(iter->req.pid, ns);
		if (iter->parent)
			get_task_struct(iter->parent);
		rcu_read_unlock();
	}

	switch (iter->req.dump_strategy) {
	case TASK_DIAG_DUMP_ONE:
		if (iter->parent == NULL)
			return ERR_PTR(-ESRCH);
		iter->pos = iter->cb->pos;
		if (iter->pos == 0) {
			iter->task = iter->parent;
			get_task_struct(iter->task);
		} else
			iter->task = NULL;
		return iter->task;
	case TASK_DIAG_DUMP_THREAD:
		if (iter->parent == NULL)
			return ERR_PTR(-ESRCH);

		iter->pos = iter->cb->pos;
		iter->task = task_first_tid(iter->parent, 0, iter->pos, ns);
		return iter->task;

	case TASK_DIAG_DUMP_CHILDREN:
		if (iter->parent == NULL)
			return ERR_PTR(-ESRCH);

		iter->pos = iter->cb->pos;
		iter->task = task_next_child(iter->parent, NULL, iter->pos);
		return iter->task;

	case TASK_DIAG_DUMP_ALL:
		iter->tgid.tgid = iter->cb->pid;
		iter->tgid.task = NULL;
		iter->tgid = next_tgid(ns, iter->tgid);
		return iter->tgid.task;

	case TASK_DIAG_DUMP_ALL_THREAD:
		iter->pos = iter->cb->pos;
		iter->tgid.tgid = iter->cb->pid;
		iter->tgid.task = NULL;
		iter->tgid = next_tgid(ns, iter->tgid);
		if (!iter->tgid.task)
			return NULL;

		iter->task = task_first_tid(iter->tgid.task, 0, iter->pos, ns);
		if (!iter->task) {
			iter->pos = 0;
			iter->tgid.tgid += 1;
			iter->tgid = next_tgid(ns, iter->tgid);
			iter->task = iter->tgid.task;
			if (iter->task)
				get_task_struct(iter->task);
		}
		return iter->task;
	}

	return ERR_PTR(-EINVAL);
}

static struct task_struct *iter_next(struct task_iter *iter)
{
	struct pid_namespace *ns = task_active_pid_ns(current);

	switch (iter->req.dump_strategy) {
	case TASK_DIAG_DUMP_ONE:
		iter->pos++;
		iter->cb->pos = iter->pos;
		if (iter->task)
			put_task_struct(iter->task);
		iter->task = NULL;
		return NULL;
	case TASK_DIAG_DUMP_THREAD:
		iter->pos++;
		iter->task = task_next_tid(iter->task);
		iter->cb->pos = iter->pos;
		iter->cb->pid = task_pid_nr_ns(iter->task, ns);
		return iter->task;
	case TASK_DIAG_DUMP_CHILDREN:
		iter->pos++;
		iter->task = task_next_child(iter->parent, iter->task, iter->pos);
		iter->cb->pos = iter->pos;
		return iter->task;

	case TASK_DIAG_DUMP_ALL:
		iter->tgid.tgid += 1;
		iter->tgid = next_tgid(ns, iter->tgid);
		iter->cb->pid = iter->tgid.tgid;
		return iter->tgid.task;

	case TASK_DIAG_DUMP_ALL_THREAD:
		iter->pos++;
		iter->task = task_next_tid(iter->task);
		if (!iter->task) {
			iter->pos = 0;
			iter->tgid.tgid += 1;
			iter->tgid = next_tgid(ns, iter->tgid);
			iter->task = iter->tgid.task;
			if (iter->task)
				get_task_struct(iter->task);
		}

		/* save current position */
		iter->cb->pid = iter->tgid.tgid;
		iter->cb->pos = iter->pos;

		return iter->task;
	}

	return NULL;
}

static struct nlattr *task_diag_fill_attr(struct sk_buff *skb,
				struct task_diag_cb *args)
{
	struct nlattr *attr;
	void *reply;

	reply = genlmsg_put(skb, 0, 0, &taskstats_family, 0, TASK_DIAG_CMD_GET);
	if (reply == NULL)
		return NULL;

	attr = nla_reserve(skb, TASK_DIAG_ARGS, sizeof(*args));

	genlmsg_end(skb, reply);

	return attr;
}

SYSCALL_DEFINE4(taskdiag, const char __user *, ureq,
		size_t, req_size, char __user *, uresp,
		size_t, resp_size)
{
	struct nlattr *attr;
	char buf[128];
	struct task_struct *task;
	struct task_iter iter = {};
	struct sk_buff *skb;
	struct task_diag_cb prev_args = {}, diag_args = {};
	size_t off = 0;
	int size = req_size;
	int rc = -ESRCH;

	if (req_size < nla_total_size(sizeof(struct task_diag_pid))
			+ nla_total_size(sizeof(long[6])))
		return -EINVAL;
	if (req_size > sizeof(buf))
		return -EMSGSIZE;
	if (copy_from_user(&buf, ureq, req_size))
		return -EFAULT;

	attr = (void *) buf;
	if (nla_type(attr) != TASK_DIAG_CMD_GET)
		return -EINVAL;
	if (nla_len(attr) != sizeof(iter.req))
		return -EINVAL;
	memcpy(&iter.req, nla_data(attr), nla_len(attr));

	attr = nla_next(attr, &size);
//	if (nla_type(attr) != TASK_DIAG_CMD_CURSOR)
//		return -EINVAL;
	if (nla_len(attr) != sizeof(diag_args))
		return -EINVAL;
	memcpy(&diag_args, nla_data(attr), nla_len(attr));

	skb = alloc_skb(resp_size, GFP_KERNEL);
	if (!skb)
		return -EMSGSIZE;

	iter.cb  = &diag_args;

	task = iter_start(&iter);
	if (IS_ERR(task))
		return PTR_ERR(task);

	rc = 0;
	for (; task; task = iter_next(&iter)) {
		if (!ptrace_may_access(task, PTRACE_MODE_READ))
			continue;

		rc = task_diag_fill(task, skb, &iter.req,
				0, 0, &diag_args);
		if (rc < 0) {
			put_task_struct(task);
			if (rc != -EMSGSIZE)
				goto err;
		}

		if (off + skb->len > resp_size - nla_total_size(sizeof(diag_args)))
			goto out;

		if (copy_to_user(uresp + off, skb->data, skb->len)) {
			rc = -EFAULT;
			goto err;
		}
		off += skb->len;
		skb_trim(skb, 0);
		memcpy(&prev_args, &diag_args, sizeof(prev_args));

		if (rc < 0)
			goto out;
	}

	skb_trim(skb, 0);
	{
		struct nlmsghdr *nlh;
		nlh = nlmsg_put(skb, 0, 0,
			 NLMSG_DONE, 0, NLM_F_MULTI);
		if (!nlh) {
			rc = -EMSGSIZE;
			goto err;
		}
	}
	if (copy_to_user(uresp + off, skb->data, skb->len)) {
		rc = -EFAULT;
		goto err;
	}
	off += skb->len;
	rc = off;
	goto err;
out:
	skb_trim(skb, 0);
	attr = task_diag_fill_attr(skb, &diag_args);
	if (attr == NULL) {
		rc = -EMSGSIZE;
		goto err;
	}
	memcpy(nla_data(attr), &prev_args, sizeof(prev_args));
	if (copy_to_user(uresp + off, skb->data, skb->len)) {
		rc = -EFAULT;
		goto err;
	}
	off += skb->len;

	rc = off;
err:
	nlmsg_free(skb);
	return rc;
}
