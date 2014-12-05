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

#include "task_diag_comm.h"
#include "taskdiag.h"

int tasks;


extern int _show_task(struct nlmsghdr *hdr)
{
	tasks++;
	return show_task(hdr);
}

int main(int argc, char *argv[])
{
	int exit_status = 1;
	int rc, rep_len, id;
	int nl_sd = -1;
	struct {
		struct task_diag_pid req;
	} pid_req;
	char buf[4096];

	quiet = 0;

	pid_req.req.show_flags = 0;
	pid_req.req.dump_stratagy = TASK_DIAG_DUMP_ALL;
	pid_req.req.pid = 1;

	nl_sd = create_nl_socket(NETLINK_GENERIC);
	if (nl_sd < 0)
		return -1;

	id = get_family_id(nl_sd);
	if (!id)
		goto err;

	rc = send_cmd(nl_sd, id, getpid(), TASKDIAG_CMD_GET,
		      TASKDIAG_CMD_ATTR_GET, &pid_req, sizeof(pid_req), 1);
	pr_info("Sent pid/tgid, retval %d\n", rc);
	if (rc < 0)
		goto err;

	while (1) {
		int err;

		rep_len = recv(nl_sd, buf, sizeof(buf), 0);
		pr_info("received %d bytes\n", rep_len);

		if (rep_len < 0) {
			pr_perror("Unable to receive a response\n");
			goto err;
		}

		if (rep_len == 0)
			break;

		err = nlmsg_receive(buf, rep_len, &_show_task);
		if (err < 0)
			goto err;
		if (err == 0)
			break;
	}
	printf("tasks: %d\n", tasks);

	exit_status = 0;
err:
	close(nl_sd);
	return exit_status;
}
