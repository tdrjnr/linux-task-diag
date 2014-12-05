#ifndef __TASK_DIAG_COMM__
#define __TASK_DIAG_COMM__

#include <stdio.h>

#include <linux/genetlink.h>
#include "task_diag.h"

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)

#define pr_err(fmt, ...)				\
		fprintf(stderr, fmt"\n", ##__VA_ARGS__)

#define pr_perror(fmt, ...)				\
		fprintf(stderr, fmt " : %m\n", ##__VA_ARGS__)

extern int quiet;
#define pr_info(fmt, arg...)			\
	do {					\
		if (!quiet)			\
			printf(fmt, ##arg);	\
	} while (0)				\

struct genl_ops ops;
int parse_cb(struct nl_msg *msg, void *arg);

#endif /* __TASK_DIAG_COMM__ */
