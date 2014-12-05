#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <getopt.h>

#include <linux/netlink.h>
#include <netlink/socket.h>
#include <linux/genetlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <linux/socket.h>

#include "task_diag.h"
#include "taskstats.h"
#include "task_diag_comm.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK	270
#endif

#ifndef NETLINK_SCM_PID
#define NETLINK_SCM_PID	11
#endif

void usage(char *name)
{
	pr_err("Usage: %s command [options]", name);
	pr_err(
"Commands:\n"
"\tall         - dump all processes\n"
"\tAll         - dump all threads\n"
"\tthreads     - dump all thread for the specified process\n"
"\tchildren    - dump all thread for the specified process\n"
"\tone         - dump the specified process\n"
"Options:\n"
"\t-p|--pid    - PID of the required process\n"
"\t-n|--pidns  - PID of a process from the required pid namespace\n"
"\t-m|--maps   - dump memory regions\n"
"\t-s|--smaps  - dump statistics for memory regions\n"
"\t-c|--cred   - dump credentials"
);
}
int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	int exit_status = 1;
	int id, ns_pid = 0;
	struct task_diag_pid req;
	struct nl_msg *msg;
	__u32 last_pid = 0;
	int opt, idx;
	void *hdr;
	int err;
	static const char short_opts[] = "p:n:cms";
	static struct option long_opts[] = {
		{ "pid",	required_argument, 0, 'p' },
		{ "pidns",	required_argument, 0, 'n' },
		{ "maps",	no_argument, 0, 'm' },
		{ "smaps",	no_argument, 0, 's' },
		{ "cred",	no_argument, 0, 'c' },
		{},
	};

	req.show_flags = TASK_DIAG_SHOW_BASE;

	if (argc < 2) {
		pr_err("Usage: %s type pid scm_pid", argv[0]);
		return 1;
	}

	req.pid = 0; /* dump all tasks by default */

	switch (argv[1][0]) {
	case 'c':
		req.dump_strategy = TASK_DIAG_DUMP_CHILDREN;
		break;
	case 't':
		req.dump_strategy = TASK_DIAG_DUMP_THREAD;
		break;
	case 'o':
		req.dump_strategy = TASK_DIAG_DUMP_ONE;
		break;
	case 'a':
		req.dump_strategy = TASK_DIAG_DUMP_ALL;
		req.pid = 0;
		break;
	case 'A':
		req.dump_strategy = TASK_DIAG_DUMP_ALL_THREAD;
		req.pid = 0;
		break;
	default:
		usage(argv[0]);
		return 1;
	}

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;
		switch (opt) {
		case 'p':
			req.pid = atoi(optarg);
			break;
		case 'n':
			ns_pid = atoi(optarg);
			break;
		case 'c':
			req.show_flags |= TASK_DIAG_SHOW_CRED;
			break;
		case 'm':
			req.show_flags |= TASK_DIAG_SHOW_VMA;
			break;
		case 's':
			req.show_flags |= TASK_DIAG_SHOW_VMA_STAT | TASK_DIAG_SHOW_VMA;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	sock = nl_socket_alloc();
	if (sock == NULL)
		return -1;
	nl_connect(sock, NETLINK_GENERIC);

	err = genl_register_family(&ops);
	if (err < 0) {
		pr_err("Unable to register Generic Netlink family");
		return 1;
	}

	err = genl_ops_resolve(sock, &ops);
	if (err < 0) {
		pr_err("Unable to resolve family name");
		return -1;
	}

	id = genl_ctrl_resolve(sock, TASKSTATS_GENL_NAME);
	if (id == GENL_ID_GENERATE)
		return -1;


	{
		int val = 1;
		if (setsockopt(nl_socket_get_fd(sock), SOL_NETLINK, NETLINK_SCM_PID, &val, sizeof(val)))
			return -1;
	}

	msg = nlmsg_alloc();
	if (msg == NULL) {
		pr_err("Unable to allocate netlink message");
		return -1;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, id,
			  0, NLM_F_DUMP, TASK_DIAG_CMD_GET, 0);
	if (hdr == NULL) {
		pr_err("Unable to write genl header");
		return -1;
	}

	err = nla_put(msg, TASKSTATS_CMD_GET, sizeof(req), &req);
	if (err < 0) {
		pr_err("Unable to add attribute: %s", nl_geterror(err));
		return -1;
	}

	if (ns_pid) {
		struct ucred cred = {.pid = ns_pid};
		nlmsg_set_creds(msg, &cred);
	}

	err = nl_send_auto_complete(sock, msg);
	if (err < 0) {
		pr_err("Unable to send message: %s", nl_geterror(err));
		return -1;
	}

	nlmsg_free(msg);

	err = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
			parse_cb, &last_pid);
	if (err < 0) {
		pr_err("Unable to modify valid message callback");
		goto err;
	}
	err = nl_socket_modify_cb(sock, NL_CB_FINISH, NL_CB_CUSTOM,
			parse_cb, &last_pid);
	if (err < 0) {
		pr_err("Unable to modify valid message callback");
		goto err;
	}


	err = nl_recvmsgs_default(sock);
	if (err < 0) {
		pr_err("Unable to receive message: %s", nl_geterror(err));
		goto err;
	}

	exit_status = 0;
err:
	nl_close(sock);
	nl_socket_free(sock);
	return exit_status;
}
