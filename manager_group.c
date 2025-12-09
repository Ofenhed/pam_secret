#include "manager_group.h"
#include "utils.h"
#include <grp.h>
#include <limits.h>

#ifdef SERVICE_GROUP
#define SERVICE_GROUP_STR STRINGIZE_VALUE_OF(SERVICE_GROUP)
#else
#define SERVICE_GROUP_STR "enc-auth"
#endif
const char *manager_group_name = SERVICE_GROUP_STR;

gid_t manager_group() {
  static gid_t manager_group = INVALID_GROUP;
  if (manager_group == INVALID_GROUP) {
    struct group *gr = getgrnam(SERVICE_GROUP_STR);
    if (gr == NULL) {
      errno = ENOENT;
      perror("Could not find group " SERVICE_GROUP_STR);
      return -1;
    }
    manager_group = gr->gr_gid;
  }
  return manager_group;
}

