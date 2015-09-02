#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/genetlink.h>

#include "task_diag.h"
#include "taskstats.h"
#include "task_diag_comm.h"

int quiet = 0;

/*
 * Create a raw netlink socket and bind
 */
int create_nl_socket(int protocol)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
		goto error;

	return fd;
error:
	close(fd);
	return -1;
}


int send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
	     __u8 genl_cmd, __u16 nla_type,
	     void *nla_data, int nla_len, int dump)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	if (dump)
		msg.n.nlmsg_flags |= NLM_F_DUMP;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr));
	if (r != buflen) {
		pr_perror("Unable to send %d (%d)", r, buflen);
		return -1;
	}
	return 0;
}


/*
 * Probe the controller in genetlink to find the family id
 * for the TASKDIAG family
 */
int get_family_id(int sd)
{
	char name[100];
	struct msgtemplate ans;

	int id = 0, rc;
	struct nlattr *na;
	int rep_len;

	strcpy(name, TASKSTATS_GENL_NAME);
	rc = send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, (void *)name,
			strlen(TASKSTATS_GENL_NAME) + 1, 0);
	if (rc < 0)
		return -1;

	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (ans.n.nlmsg_type == NLMSG_ERROR ||
	    (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID)
		id = *(__u16 *) NLA_DATA(na);

	return id;
}

int nlmsg_receive(void *buf, int len, int (*cb)(struct nlmsghdr *))
{
	struct nlmsghdr *hdr;

	for (hdr = (struct nlmsghdr *)buf;
			NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {

		if (hdr->nlmsg_type == NLMSG_DONE) {
			int *len = (int *)NLMSG_DATA(hdr);

			if (*len < 0) {
				pr_err("ERROR %d reported by netlink (%s)\n",
					*len, strerror(-*len));
				return *len;
			}

			return 0;
		}

		if (hdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);

			if (hdr->nlmsg_len - sizeof(*hdr) < sizeof(struct nlmsgerr)) {
				pr_err("ERROR truncated\n");
				return -1;
			}

			if (err->error == 0)
				return 0;

			return -1;
		}
		if (cb && cb(hdr))
			return -1;
	}

	return 1;
}

long args[6];

int show_task(struct nlmsghdr *hdr)
{
	int msg_len;
	struct msgtemplate *msg;
	struct nlattr *na;
	int len;

	msg_len = GENLMSG_PAYLOAD(hdr);

	msg = (struct msgtemplate *)hdr;
	na = (struct nlattr *) GENLMSG_DATA(msg);
	len = 0;
	while (len < msg_len) {
		len += NLA_ALIGN(na->nla_len);
		switch (na->nla_type) {
		case TASK_DIAG_ARGS:
			memcpy(args, NLA_DATA(na), sizeof(args));
			printf("zzz %lx %lx %lx %lx %lx %lx\n", args[0], args[1], args[2], args[3], args[4], args[5]);
			break;
		case TASK_DIAG_PID:
		{
			pid_t pid;

			/* For nested attributes, na follows */
			pid = *((pid_t *) NLA_DATA(na));
			pr_info("pid %d\n", pid);
			break;
		}
		case TASK_DIAG_BASE:
		{
			struct task_diag_base *msg;

			/* For nested attributes, na follows */
			msg = (struct task_diag_base *) NLA_DATA(na);
			pr_info("pid %d ppid %d comm %s\n", msg->pid, msg->ppid, msg->comm);
			break;
		}
		case TASK_DIAG_CRED:
		{
			struct task_diag_creds *creds;

			creds = (struct task_diag_creds *) NLA_DATA(na);
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
			break;
		}
		case TASK_DIAG_STAT:
			break;
/*		case TASK_DIAG_VMA:
		{
			struct task_diag_vma *vma;

			vma = (struct task_diag_vma *) NLA_DATA(na);
			pr_info("%016llx-%016llx %llx\n", vma->start, vma->end, vma->vm_flags);
			break;
		}
		case TASK_DIAG_VMA_NAME:
		{
			char *name;

			name = (char *) NLA_DATA(na);
			pr_info("vma %s\n", name);
			break;
		}*/
		default:
			pr_info("Unknown nla_type %d\n",
				na->nla_type);
		}
		na = (struct nlattr *) (GENLMSG_DATA(msg) + len);
	}

	return 0;
}
