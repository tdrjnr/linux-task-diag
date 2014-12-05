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

#include <linux/netlink.h>
#include <netlink/socket.h>
#include <linux/genetlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>

#include "task_diag.h"
#include "taskstats.h"
#include "task_diag_comm.h"

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	int exit_status = 1;
	int id;
	struct task_diag_pid req;
	struct nl_msg *msg;
	void *hdr;
	int err;


	req.pid = 0;
	if (argc >= 2)
		req.pid = atoi(argv[1]);
	if (req.pid == 0) {
		pr_err("Usage: %s PID\n", argv[0]);
		return 1;
	}
	req.show_flags = TASK_DIAG_SHOW_BASE | TASK_DIAG_SHOW_CRED |
				TASK_DIAG_SHOW_VMA | TASK_DIAG_SHOW_VMA_STAT;

	sock = nl_socket_alloc();
	if (sock == NULL)
		return -1;
	nl_connect(sock, NETLINK_GENERIC);

	err = genl_register_family(&ops);
	if (err < 0) {
		pr_err("Unable to register Generic Netlink family");
		return -1;
	}

	err = genl_ops_resolve(sock, &ops);
	if (err < 0) {
		pr_err("Unable to resolve family name");
		return -1;
	}

	id = genl_ctrl_resolve(sock, TASKSTATS_GENL_NAME);
	if (id == GENL_ID_GENERATE)
		return -1;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		pr_err("Unable to allocate netlink message");
		return -1;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, id,
			  0, 0, TASK_DIAG_CMD_GET, 0);
	if (hdr == NULL) {
		pr_err("Unable to write genl header");
		return -1;
	}

	err = nla_put(msg, TASK_DIAG_CMD_GET,
				sizeof(struct task_diag_pid), &req);
	if (err < 0) {
		pr_err("Unable to add attribute: %s", nl_geterror(err));
		return -1;
	}

	err = nl_send_auto_complete(sock, msg);
	if (err < 0) {
		pr_err("Unable to send message: %s", nl_geterror(err));
		return -1;
	}

	nlmsg_free(msg);

	err = nl_socket_modify_cb(sock, NL_CB_VALID,
				NL_CB_CUSTOM, parse_cb, NULL);
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
