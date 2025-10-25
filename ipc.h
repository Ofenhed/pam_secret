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
} kind;
  union {
      int data_len;
  };
} msg_info_t;

typedef struct {
    union {
        int fd;
    };
} msg_context_t;

inline static msg_context_t fd_to_context(int fd) {
    msg_context_t c = {0};
    c.fd = fd;
    return c;
}

int msg_content_length(msg_info_t kind);

int recv_peer_msg(int sock, msg_info_t *info, msg_context_t data[2]);
int send_peer_msg(int sock, msg_info_t info, msg_context_t context[], int context_len, int options);

int get_sock_path_for_user(char *dest, int dest_len);
