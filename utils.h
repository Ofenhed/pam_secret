#pragma once

#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#define ARR_LEN(x) (sizeof(x) / sizeof(x[0]))
#define ARR_END(x) (x + ARR_LEN(x))

#if !(defined(SUDO_BIN) || defined(PKEXEC_BIN))
#define PKEXEC_BIN "/usr/bin/sudo"
#endif

#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)

#define LINESTR1(file, line) file ":" #line
#define LINESTR(file, line) LINESTR1(file, line)
#define LINE LINESTR(__FILE__, __LINE__)
#define PROP_ERR_WITH(x, y) { if ((x) == -1) { { y } return -1; } }
#define PROP_ERR(x) PROP_ERR_WITH(x, perror("Boom at " LINE "!");)

#define EXPORTED __attribute__ ((visibility ("default") ))

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

int exec_blocking_io(const char *prog, char *const argv[], const char input[], int input_len, char *output, int output_len, int *bytes_read);

static int exec_blocking_output(const char *prog, char *const argv[], char *output, int output_len, int *bytes_read) {
    return exec_blocking_io(prog, argv, NULL, 0, output, output_len, NULL);
}

static int exec_blocking_cstring_output(const char *prog, char *const argv[], char *output, int output_len) {
    return exec_blocking_output(prog, argv, output, output_len, NULL);
}

static int exec_blocking(const char *prog, char* const argv[]) {
    return exec_blocking_output(prog, argv, NULL, 0, NULL);
}

const char *vbufnprintf(char **buf, const char *const buf_end, const char *format, va_list list);
const char *bufnprintf(char **buf, const char *const buf_end, const char *format, ...);
int add_arg(const char ***args, const char *const *const args_end, const char* arg);

inline static int inherit_fd(int fd) {
    //return fcntl(fd, F_SETFD, FD_CLOEXEC, 0);
    //return fd;
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
