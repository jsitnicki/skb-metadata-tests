/*
 * LD_PRELOAD for a shell to change namespace with 'cd'.
 *
 * Example use:
 *
 *   $ sudo LD_PRELOAD=./chdir_setns.so bash
 *   # touch /tmp/net-ns
 *   # unshare --net=/tmp/net-ns ip link set dev lo up
 *   # nsenter --net=/tmp/net-ns readlink /proc/self/ns/net
 *   net:[4026532723]
 *   # readlink /proc/self/ns/net
 *   net:[4026531840]
 *   # cd /tmp/net-ns
 *   bash: cd: /tmp/net-ns: Is a named type file
 *   # readlink /proc/self/ns/net
 *   net:[4026532723]
 *   #
 *
 * Build with:
 *
 *   cc -Wall -Wextra -fPIC -shared -o chdir_setns.so chdir_setns.c -ldl
 *
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

static void auto_close(int *fd)
{
	if (fd && *fd >= 0)
		close(*fd);
}

#define auto_close __attribute__((cleanup(auto_close)))

static int try_setns(const char *path) {
        auto_close int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

        return setns(fd, 0);
}

int chdir(const char *path)
{
	int (*sys_chdir)(const char *) = dlsym(RTLD_NEXT, "chdir");
        int ret;

	ret = (*sys_chdir)(path);
	if (ret == 0 || errno != ENOTDIR)
		return ret;

	ret = try_setns(path);
	if (ret == 0)
		errno = EISNAM;	/* mask setns success */

	return -1;
}
