#include "utils.h"
#include "extern.h"
#include "log.h"
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
#include <termios.h>
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

const char *bufnprintf(char **restrict buf, const char *restrict const buf_end,
                       const char *format, ...) {
  va_list list;
  va_start(list, format);
  auto ret = vbufnprintf(buf, buf_end, format, list);
  va_end(list);
  return ret;
}

int read_secret_password(char *restrict password, int password_len,
                         const char *format, ...) {
  struct termios saved_flags, tmp_flags;
  va_list format_args;
  int tty_detected = isatty(fileno(stdin));

  va_start(format_args, format);
  if (tty_detected) {
    tcgetattr(fileno(stdout), &saved_flags);
    tmp_flags = saved_flags;
    tmp_flags.c_lflag &= ~ECHO;
    tmp_flags.c_lflag |= ECHONL;

    PROP_ERR(tcsetattr(fileno(stdout), TCSANOW, &tmp_flags));

    vfprintf(stdout, format, format_args);
    fflush(stdout);
  }
  va_end(format_args);
  char *password_ptr = password;
  const char *const password_end = password_ptr + password_len;
  int read_error;
  while (password_ptr < password_end && !feof(stdin) &&
         (*password_ptr = fgetc(stdin)) && *password_ptr != '\n') {
    if (*password_ptr == -1) {
      read_error = errno;
      break;
    }
    ++password_ptr;
  }
  if (password_ptr == password_end) {
    return -1;
  }
  if (tty_detected) {
    PROP_ERR(tcsetattr(fileno(stdout), TCSANOW, &saved_flags));
  }
  if (*password_ptr == -1) {
    errno = read_error;
    return -1;
  }
  return password_ptr - password;
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

const char *get_runtime_dir(uid_t(get_target_user)(void)) {
  static char runtime_dir_buf[32];
  static const char *socket_dir = NULL;
  if (socket_dir == NULL) {
    // if ((socket_dir = secure_getenv("XDG_RUNTIME_DIR")) == NULL) {
    int len = snprintf(runtime_dir_buf, ARR_LEN(runtime_dir_buf),
                       "/run/user/%u", get_target_user());
    if (len < ARR_LEN(runtime_dir_buf))
      socket_dir = runtime_dir_buf;
    //}
  }
  return socket_dir;
}

int write_random_data(char *target, int secret_length) {
  log_debug("Writing %i bytes to %p\n", secret_length, target);
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
  dup2(null, stdout_fd);
  dup2(null, stderr_fd);
#endif
}

inline void *__crit_mmap(const char *call_source, void *addr, size_t len,
                         int prot, int flags, int fd, __off_t offset) {
  if (len == 0) {
    log_error("Tried to allocate zero bytes at %s", call_source);
    return NULL;
  }
  void *result = mmap(addr, len, prot, flags, fd, offset);
  if (result == MAP_FAILED) {
    log_error("Critical mmap failed at %s\n", call_source);
    exit(EXIT_FAILURE);
  }
  return result;
}

void *__memfd_secret_alloc(int size) {
  int secret;
  PROP_CRIT(secret = memfd_secret(O_CLOEXEC));
  PROP_CRIT(ftruncate(secret, size));
  void *ptr =
      crit_mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, secret, 0);
  PROP_CRIT(close(secret));
  return ptr;
}
