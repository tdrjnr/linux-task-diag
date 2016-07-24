#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#define NSIO    0xb7
#define NS_GET_USERNS   _IO(NSIO, 0x1)

int main(int argc, char *argv[])
{
	char buf[128], path[] = "/proc/self/fd/0123456789";
	int ns, uns, ret;

	ns = open(argv[1], O_RDONLY);
	if (ns < 0)
		return 1;

	uns = ioctl(ns, NS_GET_USERNS);
	if (uns < 0)
		return 1;

	snprintf(path, sizeof(path), "/proc/self/fd/%d", uns);
	ret = readlink(path, buf, sizeof(buf) - 1);
	if (ret < 0)
		return 1;
	buf[ret] = 0;

	printf("%s\n", buf);

	return 0;
}
