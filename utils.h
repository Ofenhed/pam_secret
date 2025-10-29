#pragma once

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#define ARR_LEN(x) (sizeof(x) / sizeof(x[0]))
#define ARR_END(x) (x + ARR_LEN(x))
#define STR_LEN(x) (ARR_LEN(x) - 1)
#define STR_END(x) (x + STR_LEN(x))

#if !(defined(SUDO_BIN) || defined(PKEXEC_BIN))
#define PKEXEC_BIN "/usr/bin/sudo"
#endif

#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)

#define LINESTR1(file, line) file ":" #line
#define LINESTR(file, line) LINESTR1(file, line)
#define LINE LINESTR(__FILE__, __LINE__)

#define CRITICAL_ERR(x)                                                        \
  {                                                                            \
    perror(LINE " " x);                                                        \
    exit(EXIT_FAILURE);                                                        \
  }

#define PROP_ERR_WITH(x, y)                                                    \
  {                                                                            \
    if ((x) == -1) {                                                           \
      perror("Boom at " LINE "!");                                             \
      {                                                                        \
        y                                                                      \
      }                                                                        \
      return -1;                                                               \
    }                                                                          \
  }
#define PROP_ERR(x) PROP_ERR_WITH(x, perror("Boom at " LINE "!");)
#define PROP_CRIT(x)                                                           \
  {                                                                            \
    if ((x) == -1)                                                             \
      CRITICAL_ERR()                                                           \
  }

#define EXPORTED __attribute__((visibility("default")))

#ifdef DEBUG
#define DEBUG_PROP_ERR(x) PROP_ERR(x)
#else
#define DEBUG_PROP_ERR(x) (x)
#endif

#ifdef SUDO_BIN
#define AS_USER_BIN SUDO_BIN
#define AS_USER(user) AS_USER_BIN, "-u", user, "--"
#else
#ifdef PKEXEC_BIN
#define AS_USER_BIN PKEXEC_BIN
#define AS_USER(user) AS_USER_BIN, "--user", user
#else
#error "Unreachable?"
#endif
#endif

static const int PIPE_RX = 0;
static const int PIPE_TX = 1;

const char *vbufnprintf(char **buf, const char *const buf_end,
                        const char *format, va_list list);
const char *bufnprintf(char **buf, const char *const buf_end,
                       const char *format, ...);
int read_secret_password(char *restrict password, int password_len,
                         const char *format, ...);

int add_arg(const char ***args, const char *const *const args_end,
            const char *arg);
const char *get_runtime_dir();

inline static int inherit_fd(int fd) {
  // return fcntl(fd, F_SETFD, FD_CLOEXEC, 0);
  // return fd;
  int new_fd = dup(fd);
  dup2(fd, new_fd);
  return new_fd;
}

inline static int inherit_fd_as(int fd, int fd2) {
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

int write_random_data(char *target, int secret_length);
void *__crit_mmap(const char *call_source, void *addr, size_t len, int prot,
                  int flags, int fd, __off_t offset);
#define crit_mmap(ADDR, LEN, PROT, FLAGS, FD, OFFSET)                          \
  __crit_mmap(LINE, ADDR, LEN, PROT, FLAGS, FD, OFFSET)

void *__memfd_secret_alloc(int size);
#define crit_memfd_secret_alloc(PTR) (PTR = __memfd_secret_alloc(sizeof(*PTR)))
#define crit_munmap(PTR) PROP_CRIT(munmap(PTR, sizeof(*PTR)))
