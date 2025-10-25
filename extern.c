#include "extern.h"
#include <sys/syscall.h>

int memfd_secret(unsigned int flags) {
    return syscall(SYS_memfd_secret, flags);
}

int pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(SYS_pidfd_open, pid, flags);
}
