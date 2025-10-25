#include "creds.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/nsfs.h>
#include <sys/stat.h>

#define CRIT_ERR(x) { if ((x) == -1) { perror("Critical error when checking namespaces"); exit(1); } }

int init_privileged() {
    if (get_system_secret_fd() == -1) {
        perror("Could not initialize process privileges");
        exit(1);
    }
    return 0;
}

void assert_no_parent(const char *path) {
    int ns, parent_ns;
    CRIT_ERR(ns = open(path, O_CLOEXEC | O_RDONLY, 0));
    CRIT_ERR(parent_ns = ioctl(ns, NS_GET_USERNS));
    struct stat fdstat, parentstat;
    CRIT_ERR(fstat(ns, &fdstat));
    CRIT_ERR(fstat(parent_ns, &parentstat));
    if (fdstat.st_dev != parentstat.st_dev || fdstat.st_ino != parentstat.st_ino) {
        fprintf(stderr, "This is not allowed to run inside of a namespace\n%lu:%lu /= %lu:%lu\n", fdstat.st_dev, fdstat.st_ino, parentstat.st_dev, parentstat.st_ino);
        exit(EACCES);
    }
}

void assert_no_namespace() {
    // TODO: Fix namespace checking
    //assert_no_parent("/proc/self/ns/user");
}
