#pragma once
#include <sys/types.h>

int ftruncate(int fd, off_t length);
long syscall(long id, ...);
int memfd_secret(unsigned int flags);
int pidfd_open(pid_t pid, unsigned int flags);

