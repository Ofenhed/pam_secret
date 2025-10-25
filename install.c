#include "creds.h"
#include "utils.h"
#include <errno.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>

int maybe_create_system_secret() {
    int wd, secret_fd;
    const char *state_filename = get_system_secret_filename();
    PROP_ERR(wd = get_persistant_storage_fd());
    if (faccessat(wd, state_filename, F_OK, 0) == 0) {
      return 0;
    }
    char tmpfile[256];
    secret_fd = openat(wd, ".", O_TMPFILE | O_CLOEXEC | O_WRONLY, 0400);
    snprintf(tmpfile, ARR_LEN(tmpfile), "/proc/self/fd/%i", secret_fd);
    if (secret_fd == -1) {
        if (errno == EEXIST) {
            return 0;
        }
        perror("Could not create system secret");
        return -1;
    }
    PROP_ERR(ftruncate(secret_fd, SECRET_LEN));
    PROP_ERR(set_memfd_random(secret_fd, SECRET_LEN));
    int umask_before = umask(~0400);
    PROP_ERR(linkat(AT_FDCWD, tmpfile, wd, state_filename, AT_SYMLINK_FOLLOW));
    umask(umask_before);
    return 1;
}

int install_persistent_credentials_directory() {
  auto dir = get_persistant_storage_location();
  int me = open("/proc/self/exe", O_CLOEXEC | O_RDONLY, 0);
  int dir_fd;
  gid_t group;
  if ((group = manager_group()) == -1) {
      fprintf(stderr, "The group %s does not exist. Please create it:\n groupadd --system enc-auth\n", manager_group_name());
      return -1;
  }
  PROP_ERR(setgid(group));
  PROP_ERR(setuid(0));
  int cred_dir_perm = 02750;
  mkdir(dir, cred_dir_perm);
  PROP_ERR(dir_fd = get_persistant_storage_fd());
  PROP_ERR(fchdir(dir_fd));
  PROP_ERR(chown(".", 0, group));
  PROP_ERR(chmod(".", cred_dir_perm));
  PROP_ERR(chown("/proc/self/exe", 0, group));
  PROP_ERR(chmod("/proc/self/exe", 0750));
  return 0;
}
