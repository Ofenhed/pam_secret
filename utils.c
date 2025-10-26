#include "utils.h"
#include "extern.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

inline const char *vbufnprintf(char **buf, const char *const buf_end,
                               const char *format, va_list list) {
  if (*buf >= buf_end)
    return NULL;
  int length = buf_end - *buf;
  int wants = vsnprintf(*buf, length, format, list);
  if (wants == -1)
    perror("vsnprintf");
  if (wants >= length)
    return NULL;
  (*buf)[++wants] = 0;
  char *result = *buf;
  (*buf) += wants;
  return result;
}

const char *bufnprintf(char **buf, const char *const buf_end,
                       const char *format, ...) {
  va_list list;
  va_start(list, format);
  auto ret = vbufnprintf(buf, buf_end, format, list);
  va_end(list);
  return ret;
}

int add_arg(const char ***args, const char *const *const args_end,
            const char *arg) {
  const char **current_arg = (*args)++;
  if (*args >= args_end) {
    errno = EFAULT;
    perror("Outside of designated area");
    return -1;
  }
  *current_arg = arg;
  **args = 0;
  return 0;
}

int write_random_data(char *target, int secret_length) {
  printf("Writing %i bytes to %p\n", secret_length, target);
  int random = open("/dev/random", O_CLOEXEC | O_RDONLY);
  PROP_ERR(random);

  char *buf = target;
  const char *const buf_end = target + secret_length;
  int r;
  while (buf < buf_end && (r = read(random, buf, buf_end - buf)) != 0) {
    PROP_ERR(r);
    buf += r;
  }
  close(random);
  return 0;
}

void debug_output() {
#ifndef DEBUG
  int null = open("/dev/null", O_RDWR, 0);
  dup2(null, 1);
  dup2(null, 2);
#endif
}

inline void *__crit_mmap(const char *call_source, void *addr, size_t len,
                         int prot, int flags, int fd, __off_t offset) {
  void *result = mmap(addr, len, prot, flags, fd, offset);
  if (result == MAP_FAILED) {
    fprintf(stderr, "Critical mmap failed at %s\n", call_source);
    exit(EXIT_FAILURE);
  }
  return result;
}
