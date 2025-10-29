#pragma once

#define REPLACE_KEY_CMD_FORMAT "replace_key=%i,auth_token=%i"

int connect_daemon();
int run_daemon(const char *name, int socket_not_listening);
