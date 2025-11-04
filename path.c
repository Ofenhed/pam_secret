#include <fcntl.h>
#include <unistd.h>

int get_proc_self_fd() {
  static int proc_self_fd = -1;
  static int saved_pid = -1;
  int pid = getpid();
  if (proc_self_fd != -1 && saved_pid != pid) {
    close(proc_self_fd);
    proc_self_fd = -1;
  }
  if (proc_self_fd == -1) {
    saved_pid = pid;
    proc_self_fd = open("/proc/self", O_DIRECTORY);
  }
  return proc_self_fd;
}

__attribute__((constructor)) int get_proc_self_fds_fd() {
  static int proc_self_fd = -1;
  static int saved_pid = -1;
  int pid = getpid();
  if (proc_self_fd != -1 && saved_pid != pid) {
    close(proc_self_fd);
    proc_self_fd = -1;
  }
  if (proc_self_fd == -1) {
    int proc_self = get_proc_self_fd();
    saved_pid = pid;
    proc_self_fd = openat(proc_self, "fd", O_DIRECTORY);
    close(proc_self);
  }
  return proc_self_fd;
}
