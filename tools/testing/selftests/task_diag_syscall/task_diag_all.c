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
#include "task_diag.h"
#include "taskstats.h"

#define __NR_taskdiag 323

int tasks;


extern int _show_task(struct nlmsghdr *hdr)
{
	tasks++;
	return show_task(hdr);
}

extern long args[6];

int main(int argc, char *argv[])
{
	int exit_status = 1;
	int rc, rep_len, id;
	int nl_sd = -1;
	struct {
		struct task_diag_pid req;
	} pid_req = {};
	char buf[40960];

	quiet = 0;

//	pid_req.req.show_flags = TASK_DIAG_SHOW_VMA | TASK_DIAG_SHOW_MSG | TASK_DIAG_SHOW_CRED;
	pid_req.req.show_flags = TASK_DIAG_SHOW_BASE;
	pid_req.req.dump_strategy = TASK_DIAG_DUMP_ALL;
	pid_req.req.pid = 1;

	nl_sd = create_nl_socket(NETLINK_GENERIC);
	if (nl_sd < 0)
		return -1;

	id = get_family_id(nl_sd);
	if (!id)
		goto err;

	rc = send_cmd(nl_sd, id, getpid(), TASK_DIAG_CMD_GET,
		      TASK_DIAG_CMD_ATTR_GET, &pid_req, sizeof(pid_req), 1);
	pr_info("Sent pid/tgid, retval %d\n", rc);
	if (rc < 0)
		goto err;

	while (1) {
		int err;

		rep_len = syscall(__NR_taskdiag, &pid_req, sizeof(pid_req), buf, 128);
//		rep_len = recv(nl_sd, buf, sizeof(buf), 0);
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
		memcpy(pid_req.req.args, args, sizeof(args));
		printf("%d %lx %lx %lx %lx %lx %lx\n", err, args[0], args[1], args[2], args[3], args[4], args[5]);
	}
	printf("tasks: %d\n", tasks);

	exit_status = 0;
err:
	close(nl_sd);
	return exit_status;
}
