#include "utils.h"
#include "extern.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int exec_blocking_io(const char *prog, char *const argv[], const char *input,
                     int input_len, char *output, int output_len,
                     int *bytes_read) {
  assert((output_len == 0) == (output == NULL));
  const int rx = PIPE_RX;
  const int tx = PIPE_TX;
  int output_pipe[2] = {0};
  int input_pipe[2] = {0};
  const int save_output = output_len > 0;
  const int return_output_size = bytes_read != NULL;
  if (output_len > 0 && pipe(output_pipe) != 0) {
    perror("Output pipe failed\n");
    return -1;
  } else {
    printf("Created output pipe %i %i\n", output_pipe[0], output_pipe[1]);
  }
  if (input_len > 0 && pipe(input_pipe) != 0) {
    perror("Input pipe failed\n");
    return -1;
  } else {
    printf("Created input pipe %i %i\n", input_pipe[0], input_pipe[1]);
  }

  pid_t child = fork();
  if (child == -1) {
    perror("Fork failed");
    return -1;
  } else if (child != 0) {
    const int epollfd = epoll_create1(0);
    struct epoll_event ev_read, ev_write, events[5];
    int open_streams = 0;
    if (output_pipe[tx]) {
      close(output_pipe[tx]);
      ev_read.events = EPOLLIN;
      ev_read.data.fd = output_pipe[rx];
      if (epoll_ctl(epollfd, EPOLL_CTL_ADD, output_pipe[rx], &ev_read) == -1) {
        perror("Could not subscribe to read pipe");
      }
      ++open_streams;
    }
    if (input_pipe[rx]) {
      close(input_pipe[rx]);
      ev_write.events = EPOLLOUT;
      ev_write.data.fd = input_pipe[tx];
      if (epoll_ctl(epollfd, EPOLL_CTL_ADD, input_pipe[tx], &ev_write) == -1) {
        perror("Could not subscribe to write pipe");
      }
      ++open_streams;
    }

    char *offset_output = output;
    const char *offset_input = input;
    if (!return_output_size) {
      assert(output_len > 0);
      output_len -= 1; // Always append null byte
    }

    while (open_streams > 0) {
      int nfds = epoll_wait(epollfd, events, ARR_LEN(events), -1);
      if (nfds == -1) {
        perror("Could not wait for epoll");
      }
      for (int n = 0; n < nfds; ++n) {
        if (events[n].data.fd == input_pipe[tx]) {
          int write_len = input_len > 0
                              ? write(input_pipe[tx], offset_input, input_len)
                              : 0;
          if (write_len == -1) {
            perror("Could not read");
          } else if (write_len == 0 || input_len == 0) {
            epoll_ctl(epollfd, EPOLL_CTL_DEL, input_pipe[tx], &ev_write);
            close(input_pipe[tx]);
            --open_streams;
          } else {
            offset_input += write_len;
            input_len -= write_len;
          }
        } else if (events[n].data.fd == output_pipe[rx]) {
          int read_len = output_len > 0
                             ? read(output_pipe[rx], offset_output, output_len)
                             : 0;
          if (read_len == -1) {
            perror("Could not read");
          } else if (read_len == 0) {
            epoll_ctl(epollfd, EPOLL_CTL_DEL, output_pipe[rx], &ev_write);
            close(output_pipe[rx]);
            --open_streams;
          } else {
            offset_output += read_len;
            output_len -= read_len;
          }
        }
      }
    }
    if (bytes_read != NULL) {
      *bytes_read = offset_output - output;
      if (output_len > 0) {
        offset_output = 0;
      }
    } else {
      *offset_output = 0;
    }
    int wstatus;
    waitpid(child, &wstatus, 0);
    if (!WIFEXITED(wstatus)) {
      char errmsg[256];
      snprintf(errmsg, ARR_LEN(errmsg), "Child process %s crashed\n", prog);
      perror(errmsg);
      return -1;
    } else {
      return WEXITSTATUS(wstatus);
    }
  } else {
    if (output_pipe[rx]) {
      printf("Closing out %i\n", output_pipe[rx]);
      close(output_pipe[rx]);
      dup2(output_pipe[tx], 1);
    }
    if (input_pipe[tx]) {
      printf("Closing in %i\n", input_pipe[tx]);
      close(input_pipe[tx]);
      dup2(input_pipe[rx], 0);
    } else {
      fclose(stdin);
    }
    printf("Doing execve on %s\n", prog);
    if (execv(prog, argv) == -1) {
      perror("Child process execve failed");
      return -1;
    }
    return 0;
  }
}

int tpm_function(const char *sudoUser, char *const exec, char *const argument) {
  if (sudoUser == NULL) {
    sudoUser = "tss";
  }
  char *const tpmArgs[] = {AS_USER(sudoUser), exec, argument, NULL};
  return exec_blocking(AS_USER_BIN, tpmArgs);
}

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
