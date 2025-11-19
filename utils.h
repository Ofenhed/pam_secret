#pragma once

#include "attributes.h"
#include "log.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const int stdin_fd = 0;
static const int stdout_fd = 1;
static const int stderr_fd = 2;

#define ARR_LEN(x) (sizeof(x) / sizeof(x[0]))
#define ARR_END(x) (x + ARR_LEN(x))
#define STR_LEN(x) (ARR_LEN(x) - 1)
#define STR_END(x) (x + STR_LEN(x))

#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)

#define LINESTR1(file, line) file ":" #line
#define LINESTR(file, line) LINESTR1(file, line)
#define LINE LINESTR(__FILE__, __LINE__)

#define DEFER_MERGE(a, b) a##b
#define DEFER_VARNAME(a) DEFER_MERGE(defer_scopevar_, a)
#ifdef __clang__
static inline void defer_cleanup(void (^*b)(void)) { (*b)(); }
#define DEFER(BLOCK)                                                           \
  __attribute__((cleanup(defer_cleanup))) void (^DEFER_VARNAME(__COUNTER__))(  \
      void) = ^BLOCK
#else
#ifdef __GNUC__
#define DEFER_FUNCNAME(a) DEFER_MERGE(defer_scopefunc_, a)
#define DEFER(BLOCK)                                                           \
  void DEFER_FUNCNAME(__LINE__)(__attribute__((unused)) int *a) BLOCK;         \
  __attribute__((cleanup(DEFER_FUNCNAME(__LINE__)))) int DEFER_VARNAME(__LINE__)
#else
#error "This code uses __attribute__((cleanup)) specified for GCC or clang"
#endif
#endif

#define CRITICAL_ERR(x)                                                        \
  {                                                                            \
    log_error("Error (%s): %s", LINE, x);                                      \
    exit(EXIT_FAILURE);                                                        \
  }

#define PROP_ERR_WITH(x, y)                                                    \
  {                                                                            \
    if ((x) == -1) {                                                           \
      log_trace("Error at %s: %s", LINE, strerror(errno));                     \
      {                                                                        \
        y                                                                      \
      }                                                                        \
      return -1;                                                               \
    }                                                                          \
  }
#define PROP_ERR(x) PROP_ERR_WITH(x, ;)
#define PROP_CRIT(x)                                                           \
  {                                                                            \
    if ((x) == -1)                                                             \
      CRITICAL_ERR(strerror(errno))                                            \
  }

#ifdef DEBUG
#define DEBUG_PROP_ERR(x) PROP_ERR(x)
#else
#define DEBUG_PROP_ERR(x) (x)
#endif

static const int PIPE_RX = 0;
static const int PIPE_TX = 1;

const char *vbufnprintf(char **restrict buf, const char *restrict const buf_end,
                        const char *restrict format, va_list list)
    __attribute__((format(printf, 3, 0)));
const char *bufnprintf(char **buf, const char *const buf_end,
                       const char *format, ...)
    __attribute__((format(printf, 3, 4)));
// Create a string that is valid until the next time this function is called.
// Not thread safe!
char *tmp_sprintf(const char *restrict format, ...)
    __attribute__((format(printf, 1, 2)));
char *tmp_vsprintf(const char *restrict format, va_list list)
    __attribute__((format(printf, 1, 0)));

int read_secret_password(char *restrict password, int password_len,
                         const char *restrict format, ...)
    __attribute__((format(printf, 3, 4)));

int add_arg(const char ***args, const char *const *const args_end,
            const char *arg);
const char *get_runtime_dir(uid_t(get_target_user)(void));

__gcc_attribute__((fd_arg(1))) inline static int inherit_fd(int fd) {
  int new_fd = dup(fd);
  dup2(fd, new_fd);
  return new_fd;
}

__gcc_attribute__((fd_arg(1))) inline static int inherit_fd_as(int fd,
                                                               int fd2) {
  int new_fd = inherit_fd(fd);
  PROP_ERR(new_fd);
  if (new_fd != fd2) {
    dup2(new_fd, fd2);
    close(new_fd);
  }
  if (new_fd != fd) {
    close(fd);
  }
  return new_fd;
}

__gcc_attribute__((access(write_only,
                          1))) int write_random_data(char *target,
                                                     int secret_length);
__attr_malloc__(munmap, 1)
    __attribute__((alloc_size(3))) void *__crit_mmap(const char *call_source,
                                                     void *addr, size_t len,
                                                     int prot, int flags,
                                                     int fd, __off_t offset);
#define crit_mmap(ADDR, LEN, PROT, FLAGS, FD, OFFSET)                          \
  __crit_mmap(LINE, ADDR, LEN, PROT, FLAGS, FD, OFFSET)

__attr_malloc__(munmap, 1) void *__memfd_secret_alloc(int size);
#define crit_memfd_secret_alloc(PTR) (PTR = __memfd_secret_alloc(sizeof(*PTR)))
#define crit_munmap(PTR) PROP_CRIT(munmap(PTR, sizeof(*PTR)))
