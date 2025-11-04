#include "session_mask.h"
#include "creds.h"
#include "extern.h"
#include "utils.h"
#include <assert.h>

typedef struct {
  int offset;
  secret_state_t session_xor_mask;
} mask_state_t;

static mask_state_t *readable_mask = NULL;
static mask_state_t *writeable_mask = NULL;

const secret_state_t *get_session_mask() {
  assert(readable_mask != NULL);
  return &readable_mask->session_xor_mask;
}

__attribute__((constructor)) void init_session_mask() {
  if (writeable_mask == NULL) {
    int mask_fd;
    PROP_CRIT(mask_fd = memfd_secret(O_CLOEXEC));
    PROP_CRIT(ftruncate64(mask_fd, sizeof(*writeable_mask)));
    writeable_mask = crit_mmap(NULL, sizeof(*writeable_mask), PROT_WRITE,
                               MAP_SHARED, mask_fd, 0);
    PROP_CRIT(write_random_data((char *)&writeable_mask->session_xor_mask,
                                ARR_LEN(writeable_mask->session_xor_mask)));
    readable_mask = crit_mmap(NULL, sizeof(*readable_mask), PROT_READ,
                              MAP_SHARED, mask_fd, 0);
    close(mask_fd);
  }
}

__attribute__((destructor)) void overwrite_xor_mask() {
  munmap(readable_mask, sizeof(*readable_mask));
  write_random_data((char *)writeable_mask, sizeof(*writeable_mask));
  munmap(writeable_mask, sizeof(*writeable_mask));
}
