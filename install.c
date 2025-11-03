#include "creds.h"
#include "utils.h"
#include <errno.h>
#include <grp.h>
#include <linux/fs.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

static const mode_t SYSTEM_ENC_MODE = 0440;

int set_system_secret_immutable() {
  int wd;
  PROP_ERR(wd = get_persistent_storage_fd());
  int fd;
  PROP_ERR(fd = openat(wd, get_system_secret_filename(), O_RDONLY, 0));
  DEFER({ close(fd); });
  int attr;
  PROP_ERR(ioctl(fd, FS_IOC_GETFLAGS, &attr));
  attr |= FS_IMMUTABLE_FL;
  return ioctl(fd, FS_IOC_SETFLAGS, &attr);
}

int maybe_create_system_secret() {
  int wd, secret_fd;
  const char *state_filename = get_system_secret_filename();
  PROP_ERR(wd = get_persistent_storage_fd());
  DEFER({ set_system_secret_immutable(); });
  if (faccessat(wd, state_filename, F_OK, 0) == 0) {
    return 0;
  }
  char tmpfile[256];
  secret_fd = openat(wd, ".", O_TMPFILE | O_CLOEXEC | O_RDWR, SYSTEM_ENC_MODE);
  DEFER({ close(secret_fd); });
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
  mode_t umask_before = umask(~SYSTEM_ENC_MODE);
  PROP_ERR(linkat(AT_FDCWD, tmpfile, wd, state_filename, AT_SYMLINK_FOLLOW));
  umask(umask_before);
  return 1;
}

int install_persistent_credentials_directory() {
  auto dir = get_persistent_storage_location();
  int dir_fd;
  gid_t group;
  if ((group = manager_group()) == INVALID_GROUP) {
    const char *group_name = manager_group_name();
    fprintf(stderr,
            "The group %s does not exist. Please create it:\n groupadd "
            "--system %s\n",
            group_name, group_name);
    return -1;
  }
  PROP_ERR(setgid(group));
  PROP_ERR(setuid(0));
  mode_t cred_dir_perm = 03700;
  mkdir(dir, cred_dir_perm);
  PROP_ERR(dir_fd = get_persistent_storage_fd());
  PROP_ERR(fchdir(dir_fd));
  PROP_ERR(chown(".", 0, group));
  PROP_ERR(chmod(".", cred_dir_perm));
  return 0;
}
