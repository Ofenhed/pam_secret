#pragma once

#include <stddef.h>
typedef struct {
  enum {
    MSG_INVALID = -1,
    MSG_PEER_EOF = 0,
    MSG_CLEAR_SECRET = 1,
    MSG_HASH_DATA,
    MSG_HASH_FINALIZE,
    MSG_HASH_FINALIZED,
    MSG_NOT_AUTHENTICATED,
    MSG_AUTHENTICATE,
    MSG_AUTHENTICATED,
    MSG_UPDATE_PASSWORD,
    MSG_UPDATE_PASSWORD_SUCCESS,
    MSG_UNKNOWN_ERROR,
#ifdef DEBUG_QUERY_SECRETS
    MSG_DUMP_SECRET,
#endif
  } kind;
  union {
    size_t data_len;
#ifdef DEBUG_QUERY_SECRETS
    int secret_fd;
#endif
  };
} msg_info_t;

int msg_has_fd(msg_info_t kind);

#ifndef _Nullable
#define _Nullable
#endif

int recv_peer_msg(int sock, msg_info_t *info, int *_Nullable fd);
int send_peer_msg(int sock, msg_info_t info, int *_Nullable fd, int options);

const char *get_socket_dir();
const char *get_socket_name();
