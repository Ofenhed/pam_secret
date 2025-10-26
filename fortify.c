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

static const cap_value_t cap_list[] = {CAP_DAC_OVERRIDE};

int _gain_root_privileges(cap_t caps) {
  if (!CAP_IS_SUPPORTED(CAP_DAC_OVERRIDE)) {
    fprintf(stderr, "I can never become king!\n");
    exit(EXIT_FAILURE);
  }
  cap_flag_value_t permitted;
  PROP_ERR(cap_get_flag(caps, CAP_PERMITTED, CAP_DAC_OVERRIDE, &permitted));
  if (!permitted) {
    errno = EACCES;
    fprintf(stderr, "This program needs the CAP_DAC_OVERRIDE capability.\n");
#ifndef DEBUG
    exit(EXIT_FAILURE);
#endif
  }
  PROP_ERR(
      cap_set_flag(caps, CAP_EFFECTIVE, ARR_LEN(cap_list), cap_list, CAP_SET));
#ifdef DEBUG
  cap_set_proc(caps);
#else
  PROP_ERR(cap_set_proc(caps));
#endif
  return 0;
}

int _drop_root_privileges(cap_t caps, int permamently) {
  PROP_ERR(cap_set_flag(caps, CAP_EFFECTIVE, ARR_LEN(cap_list), cap_list,
                        CAP_CLEAR));
  if (permamently) {
    PROP_ERR(cap_set_flag(caps, CAP_PERMITTED, ARR_LEN(cap_list), cap_list,
                          CAP_CLEAR));
  }
#ifdef DEBUG
  cap_set_proc(caps);
#else
  PROP_ERR(cap_set_proc(caps));
#endif
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
  PROP_CRIT(_gain_root_privileges(caps));
  if (get_system_secret_fd() == -1) {
    perror("Could not initialize process privileges");
    exit(EXIT_FAILURE);
  }
  int my_cred;
  if ((my_cred = openat(get_persistent_storage_fd(),
                        get_persistent_secret_filename(getuid()), O_RDONLY,
                        0)) == -1) {
    perror("No user credential installed");
  }
  struct stat stats;
  fstat(my_cred, &stats);
  if (stats.st_uid != getuid()) {
    fprintf(stderr, "I don't own my secret\n");
  }
  close(my_cred);
  PROP_CRIT(_drop_root_privileges(caps, 1));
  cap_free(caps);
  return 0;
}

void assert_no_parent(const char *path) {
  int ns, parent_ns;
  PROP_CRIT(ns = open(path, O_CLOEXEC | O_RDONLY, 0));
  PROP_CRIT(parent_ns = ioctl(ns, NS_GET_USERNS));
  struct stat fdstat, parentstat;
  PROP_CRIT(fstat(ns, &fdstat));
  PROP_CRIT(fstat(parent_ns, &parentstat));
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
