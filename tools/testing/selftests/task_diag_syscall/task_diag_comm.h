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
#define NLA_DATA(na)		((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)	(len - NLA_HDRLEN)

#define pr_err(fmt, ...)				\
		fprintf(stderr, fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)				\
		fprintf(stderr, fmt " : %m\n", ##__VA_ARGS__)

extern int quiet;
#define pr_info(fmt, arg...)			\
	do {					\
		if (!quiet)			\
			printf(fmt, ##arg);	\
	} while (0)				\

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char body[4096];
};

extern int create_nl_socket(int protocol);
extern int send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
	     __u8 genl_cmd, __u16 nla_type,
	     void *nla_data, int nla_len, int dump);

extern int get_family_id(int sd);
extern int nlmsg_receive(void *buf, int len, int (*cb)(struct nlmsghdr *));
extern int show_task(struct nlmsghdr *hdr);

#endif /* __TASK_DIAG_COMM__ */
