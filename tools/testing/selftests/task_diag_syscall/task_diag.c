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

#include <linux/genetlink.h>
#include "task_diag.h"
#include "taskstats.h"
#include "task_diag_comm.h"

int main(int argc, char *argv[])
{
	int exit_status = 1;
	int rc, rep_len, id;
	int nl_sd = -1;
	struct task_diag_pid req;
	char buf[40960];
	DIR *d;
	struct dirent *de;

	req.show_flags = TASK_DIAG_SHOW_STAT | TASK_DIAG_SHOW_VMA | TASK_DIAG_SHOW_CRED;

	nl_sd = create_nl_socket(NETLINK_GENERIC);
	if (nl_sd < 0)
		return -1;

	id = get_family_id(nl_sd);
	if (!id)
		goto err;

	d = opendir("/proc");
	if (d == NULL)
		return 1;

	while ((de = readdir(d))) {
		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;

		req.pid = atoi(de->d_name);
		rc = send_cmd(nl_sd, id, getpid(), TASK_DIAG_CMD_GET,
			      TASK_DIAG_CMD_ATTR_GET, &req, sizeof(req), 0);
		pr_info("Sent pid/tgid, retval %d\n", rc);
		if (rc < 0)
			goto err;

		rep_len = recv(nl_sd, buf, sizeof(buf), 0);
		if (rep_len < 0) {
			pr_perror("Unable to receive a response\n");
			goto err;
		}
		pr_info("received %d bytes\n", rep_len);

		nlmsg_receive(buf, rep_len, &show_task);
	}

	exit_status = 0;
err:
	close(nl_sd);
	return exit_status;
}
