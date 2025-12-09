#include "path.h"
#include "utils.h"
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#ifndef PERSISTENT_CREDENTIAL_FORMAT
#define PERSISTENT_CREDENTIAL_FORMAT "protected-user-cred-%i"
#endif
#ifndef PERSISTENT_CREDENTIAL_REQUEST_PREFIX
#define PERSISTENT_CREDENTIAL_REQUEST_PREFIX ".tmp-new-"
#endif
const char *persistent_credential_request_prefix =
    PERSISTENT_CREDENTIAL_REQUEST_PREFIX;

#ifndef PASSWD_DIR
#define PASSWD_DIR "/etc/shadow.enc"
#endif
const char *persistent_storage_location = PASSWD_DIR;

#ifdef SYSTEM_SECRET_FILENAME_OVERRIDE
#define SYSTEM_SECRET_FILENAME                                                 \
  STRINGIZE_VALUE_OF(SYSTEM_SECRET_FILENAME_OVERRIDE)
#else
#define SYSTEM_SECRET_FILENAME "enc-auth"
#endif
const char *system_secret_filename = SYSTEM_SECRET_FILENAME;

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

int get_persistent_storage_fd() {
  static int storage = -1;
  if (storage == -1) {
    PROP_ERR(storage = open(persistent_storage_location, O_DIRECTORY, 0));
  }
  return storage;
}

int get_persistent_secret_filename_into(uid_t user, char *path, int max_len) {
  int written = snprintf(path, max_len, PERSISTENT_CREDENTIAL_FORMAT, user);
  if (written >= max_len) {
    return -1;
  } else {
    return written + 1;
  }
}

int get_persistent_secret_path_fd(uid_t user) {
  static int secret_path_fd = -1;
  static uid_t fd_user = INVALID_USER;
  if (secret_path_fd == -1 || fd_user != user) {
    if (secret_path_fd != -1)
      close(secret_path_fd);
    secret_path_fd = -1;
    int storage;
    PROP_ERR(storage = get_persistent_storage_fd());
    fd_user = user;
    secret_path_fd = openat(storage, get_persistent_secret_filename(user),
                            O_PATH | O_CLOEXEC, 0);
  }
  return secret_path_fd;
}

int open_persistent_secret_fd(uid_t user) {
  int secret_path_fd = get_persistent_secret_path_fd(user);
  int fd = openat(get_proc_self_fds_fd(), tmp_sprintf("%i", secret_path_fd),
                  O_RDONLY | O_CLOEXEC, 0);
  return fd;
}

int get_persistent_secret_fd(uid_t user) {
  static int secret_fd = -1;
  static uid_t fd_user = UINT_MAX;
  if (secret_fd == -1 || fd_user != user) {
    if (secret_fd != -1) {
      close(secret_fd);
    }
    secret_fd = open_persistent_secret_fd(user);
  }
  return secret_fd;
}

const char *get_persistent_secret_filename(uid_t user) {
  static char path[256];
  if (get_persistent_secret_filename_into(user, path, ARR_LEN(path)) == -1) {
    return NULL;
  } else {
    return path;
  }
}
