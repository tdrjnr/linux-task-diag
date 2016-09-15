#ifndef __LINUX_NSFS_H
#define __LINUX_NSFS_H

#include <linux/ioctl.h>

#define NSIO	0xb7
#define NS_GET_USERNS	_IO(NSIO, 0x1)

#endif /* __LINUX_NSFS_H */
