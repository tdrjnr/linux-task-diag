#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/limits.h>

#define pr_err(fmt, ...) \
		({ \
			fprintf(stderr, "%s:%d:" fmt ": %m\n", \
				__func__, __LINE__, ##__VA_ARGS__); \
			1; \
		})

#ifndef O_ATROOT
#define O_ATROOT       040000000        /* dfd is a root */
#endif
#ifndef AT_FDROOT
#define AT_FDROOT      0x2000		/* Resolve a path as if dirfd is root */
#endif

int main(int argc, char **argv)
{
	struct stat st;
	int fd, dfd;
	char path[PATH_MAX];

	dfd = open(argv[1], O_RDONLY);
	if (dfd < 0)
		return pr_err("open");

	snprintf(path, sizeof(path), "%s/test", argv[1]);
	if (mkdir(path, 755))
		return pr_err("mkdir");

	if (symlinkat("/test", dfd, "./test.link"))
		return pr_err("symlinkat");

	fd = openat(dfd, "test.link", O_RDONLY | O_ATROOT);
	if (fd < 0)
		return pr_err("open");

	if (fchdir(dfd))
		return pr_err("fchdir");

	fd = openat(AT_FDCWD, "test.link", O_RDONLY | O_ATROOT);
	if (fd < 0)
		return pr_err("open");
	close(fd);

	fd = openat(AT_FDCWD, "/test.link", O_RDONLY | O_ATROOT);
	if (fd < 0)
		return pr_err("open");
	close(fd);

	if (fstatat(AT_FDCWD, "test.link", &st, AT_FDROOT))
		return pr_err("fstatat");
	if (fstatat(dfd, "test.link", &st, AT_FDROOT))
		return pr_err("fstatat");
	if (mknodat(dfd, "./test/test.file", 0644 | S_IFREG, 0))
		return pr_err("mknod");
	if (linkat(dfd, "./test.link/test.file",
			dfd, "./test.link/test.file.link", AT_FDROOT))
		return pr_err("linkat");
	if (unlinkat(dfd, "./test.link/test.file.link", AT_FDROOT))
		return pr_err("unlinkat");

	return 0;
}
