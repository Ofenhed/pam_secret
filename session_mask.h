#include "creds.h"

typedef char mask_canary_t[8];

const secret_state_t *get_session_mask();
const mask_canary_t *get_canary();
