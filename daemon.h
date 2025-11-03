#pragma once

#include <errno.h>
#include <sys/types.h>
#define REPLACE_KEY_CMD_FORMAT "replace_key=%i,auth_token=%i"

int connect_daemon(uid_t(target_user)());
int run_daemon(const char *name, int socket_not_listening);
