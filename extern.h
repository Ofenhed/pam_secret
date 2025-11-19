#pragma once
#include <sys/types.h>
#define __STDC_WANT_LIB_EXT1__
#include <string.h>

#ifndef __STDC_LIB_EXT1__
void *memset_explicit(void *dest, int ch, size_t count)
    __attribute__((noinline));
#endif
int ftruncate(int fd, off_t length);
long syscall(long id, ...);
int memfd_secret(unsigned int flags) __attribute__((warn_unused_result));
int pidfd_open(pid_t pid, unsigned int flags)
    __attribute__((warn_unused_result));
