#include "extern.h"
#include <errno.h>
#include <sys/syscall.h>

int memfd_secret(unsigned int flags) {
  return syscall(SYS_memfd_secret, flags);
}

int pidfd_open(pid_t pid, unsigned int flags) {
  return syscall(SYS_pidfd_open, pid, flags);
}

#ifndef __STDC_LIB_EXT1__
void *memset_explicit(void *dest, int ch, size_t count) {
  if (dest == NULL) {
    errno = EINVAL;
    return NULL;
  }
  volatile unsigned char *p = dest;
  while (count--) {
    *p++ = ch;
  }
  return dest;
}
#endif
