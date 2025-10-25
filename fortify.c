#include "creds.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define CRIT_ERR(x)                                                            \
  {                                                                            \
    if ((x) == -1) {                                                           \
      perror("Critical error when checking namespaces");                       \
      exit(1);                                                                 \
    }                                                                          \
  }

static const cap_value_t cap_list[] = {CAP_DAC_OVERRIDE};

int _gain_root_privileges(cap_t caps) {
  if (!CAP_IS_SUPPORTED(CAP_DAC_OVERRIDE)) {
    fprintf(stderr, "I can never become king!\n");
    exit(1);
  }
  int caps_len = ARR_LEN(cap_list);
  cap_flag_value_t permitted;
  PROP_ERR(cap_get_flag(caps, CAP_PERMITTED, CAP_DAC_OVERRIDE, &permitted));
  if (!permitted) {
    errno = EACCES;
    fprintf(stderr, "This program needs the CAP_DAC_OVERRIDE capability.\n");
    exit(1);
  }
  PROP_ERR(
      cap_set_flag(caps, CAP_EFFECTIVE, ARR_LEN(cap_list), cap_list, CAP_SET));
  PROP_ERR(cap_set_proc(caps));
  return 0;
}

int _drop_root_privileges(cap_t caps, int permamently) {
  PROP_ERR(cap_set_flag(caps, CAP_EFFECTIVE, ARR_LEN(cap_list), cap_list,
                        CAP_CLEAR));
  if (permamently) {
    PROP_ERR(cap_set_flag(caps, CAP_PERMITTED, ARR_LEN(cap_list), cap_list,
                          CAP_CLEAR));
  }
  PROP_ERR(cap_set_proc(caps));
  return 0;
}

int gain_root_privileges() {
    auto caps = cap_get_proc();
    PROP_ERR(_gain_root_privileges(caps));
    cap_free(caps);
    return 0;
}

int drop_root_privileges(int permanently) {
    auto caps = cap_get_proc();
    PROP_ERR(_drop_root_privileges(caps, permanently));
    cap_free(caps);
    return 0;
}


int init_privileged() {
  auto caps = cap_get_proc();
  CRIT_ERR(_gain_root_privileges(caps));
  if (get_system_secret_fd() == -1) {
    perror("Could not initialize process privileges");
    exit(1);
  }
  int my_cred;
  if ((my_cred = openat(get_persistant_storage_fd(), get_uid_session_cred_persistant_path(getuid()), O_RDONLY, 0)) == -1) {
      perror("No user credential installed");
      exit(1);
  }
  struct stat stats;
  fstat(my_cred, &stats);
  if (stats.st_uid != getuid()) {
      fprintf(stderr, "I don't own my secret\n");
      exit(1);
  }
  close(my_cred);
  CRIT_ERR(_drop_root_privileges(caps, 1));
  cap_free(caps);
  return 0;
}

void assert_no_parent(const char *path) {
  int ns, parent_ns;
  CRIT_ERR(ns = open(path, O_CLOEXEC | O_RDONLY, 0));
  CRIT_ERR(parent_ns = ioctl(ns, NS_GET_USERNS));
  struct stat fdstat, parentstat;
  CRIT_ERR(fstat(ns, &fdstat));
  CRIT_ERR(fstat(parent_ns, &parentstat));
  if (fdstat.st_dev != parentstat.st_dev ||
      fdstat.st_ino != parentstat.st_ino) {
    fprintf(stderr,
            "This is not allowed to run inside of a namespace\n%lu:%lu /= "
            "%lu:%lu\n",
            fdstat.st_dev, fdstat.st_ino, parentstat.st_dev, parentstat.st_ino);
    exit(EACCES);
  }
}

void assert_no_namespace() {
  // TODO: Fix namespace checking
  // assert_no_parent("/proc/self/ns/user");
}
