#include <fcntl.h>
#include <unistd.h>

int get_proc_self_fd() {
  static int proc_self_fd = -1;
  static int pid = -1;
  if (proc_self_fd != -1 || pid != getpid()) {
    close(proc_self_fd);
    proc_self_fd = -1;
  }
  if (proc_self_fd == -1) {
    pid = getpid();
    proc_self_fd = open("/proc/self", O_DIRECTORY);
  }
  return proc_self_fd;
}

int open_proc_self_fd() {
  static int proc_self_fd = -1;
  static int pid = -1;
  if (proc_self_fd != -1 || pid != getpid()) {
    close(proc_self_fd);
    proc_self_fd = -1;
  }
  if (proc_self_fd == -1) {
    pid = getpid();
    proc_self_fd = dup(get_proc_self_fd());
  }
  return dup(proc_self_fd);
}

int get_proc_self_fds_fd() {
  static int proc_self_fd = -1;
  static int pid = -1;
  if (proc_self_fd != -1 || pid != getpid()) {
    close(proc_self_fd);
    proc_self_fd = -1;
  }
  if (proc_self_fd == -1) {
    int proc_self = open_proc_self_fd();
    pid = getpid();
    proc_self_fd = openat(proc_self, "fd", O_DIRECTORY);
    close(proc_self);
  }
  return proc_self_fd;
}

int open_proc_self_fds_fd() {
  static int proc_self_fd = -1;
  static int pid = -1;
  if (proc_self_fd != -1 || pid != getpid()) {
    close(proc_self_fd);
    proc_self_fd = -1;
  }
  if (proc_self_fd == -1) {
    pid = getpid();
    proc_self_fd = dup(get_proc_self_fds_fd());
  }
  return dup(proc_self_fd);
}

__attribute__((constructor)) void init_proc_fds() {
  close(open_proc_self_fds_fd());
}
