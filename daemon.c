#include "creds.h"
#include "extern.h"
#include "hash.h"
#include "ipc.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

int connect_daemon() {
  int sock;
  struct sockaddr_un address;
  address.sun_family = AF_UNIX;
  PROP_ERR(get_sock_path_for_user(address.sun_path, ARR_LEN(address.sun_path)));
  PROP_ERR(sock = socket(PF_UNIX, SOCK_STREAM, 0));
  PROP_ERR(connect(sock, (struct sockaddr *)&address, sizeof(address)));
  return sock;
}

typedef int server_state_t;

struct write_buf_t;
typedef struct write_buf_t {
  enum {
    WRITE_BUF_DATA,
    WRITE_BUF_CLOSE,
  } buf_kind;
  int fds_to_close[2];
  int num_fds_to_close;
  msg_info_t info;
  msg_context_t context[2];
  int context_len;
  struct write_buf_t *next;
} write_buf_t;

inline static write_buf_t *new_write_buf(write_buf_t **prev) {
  write_buf_t *b = calloc(1, sizeof(write_buf_t));
  b->buf_kind = WRITE_BUF_DATA;
  if (*prev != NULL) {
    write_buf_t *x = *prev;
    while (x->buf_kind == WRITE_BUF_DATA && x->next != NULL) {
      x = x->next;
    }
    if (x->buf_kind == WRITE_BUF_CLOSE) {
      free(b);
      return NULL;
    }
    x->next = b;
  } else {
    *prev = b;
  }
  return b;
}

inline static void free_write_buf(write_buf_t *write_buf) {
  if (write_buf != NULL) {
    write_buf_t *tail = write_buf->next;
    for (int i = 0; i < write_buf->num_fds_to_close; ++i) {
      close(write_buf->fds_to_close[i]);
    }
    free(write_buf);
    free_write_buf(tail);
  }
}

typedef struct {
  enum {
    NEW_CLIENT,
    HASHER_CLIENT,
  } client_kind;
  struct ucred cred;
  int client_has_authenticated;
  int pid;
  write_buf_t *write_buf;
  union {
    int hash_fd;
  };
  // TODO: Writing, write buffer and events?
} client_state_t;

typedef struct {
  enum {
    SERVER = 1,
    CLIENT,
    HASH_FORK,
  } peer_kind;
  int fd;
  union {
    client_state_t client_state;
    server_state_t server_state;
  };
} peer_state_t;

peer_state_t *malloc_peer_state(struct epoll_event *ev, int fd) {
  peer_state_t *mem = calloc(1, sizeof(peer_state_t));
  if (mem == NULL) {
    return NULL;
  }
  mem->client_state.write_buf = NULL;
  mem->fd = fd;
  ev->data.ptr = mem;
  return mem;
}

peer_state_t *malloc_client_state(struct epoll_event *ev, int fd) {
  peer_state_t *state = malloc_peer_state(ev, fd);
  if (state == NULL)
    return NULL;
  state->peer_kind = CLIENT;
  state->client_state.client_kind = NEW_CLIENT;
#define ADD_CLIENT_STATE(WHAT, NAME)                                           \
  {                                                                            \
    socklen_t sizeof_##name = sizeof(state->client_state.NAME);                \
    if (getsockopt(fd, SOL_SOCKET, WHAT, &state->client_state.NAME,            \
                   &sizeof_##name) == -1) {                                    \
      return NULL;                                                             \
    }                                                                          \
  }
  ADD_CLIENT_STATE(SO_PEERCRED, cred);
  ADD_CLIENT_STATE(SO_PEERPIDFD, pid);
  return state;
}

peer_state_t *peer_state(struct epoll_event *ev) {
  assert(ev->data.ptr != NULL);
  return ev->data.ptr;
}

int run_daemon(int socket_not_listening) {
  char printf_buf[256];
  char *buf_ptr = printf_buf;
  const char *const buf_end = ARR_END(printf_buf);
  peer_state_t *state_tmp;
  uid_t server_user = getuid();

  struct sockaddr_un address;
  address.sun_family = AF_UNIX;
  PROP_ERR(get_sock_path_for_user(address.sun_path, ARR_LEN(address.sun_path)));
  int umask_before = umask(077);
  unlink(address.sun_path);
  int server = socket(AF_UNIX, SOCK_STREAM, 0);
  PROP_ERR(fcntl(server, F_SETFD, FD_CLOEXEC));
  PROP_ERR(bind(server, (struct sockaddr *)(&address), sizeof(address)));
  umask(umask_before);
  int epollfd;
  PROP_ERR(epollfd = epoll_create1(O_CLOEXEC));
  struct epoll_event ev;
  ev.events = EPOLLIN;
  if (!(state_tmp = malloc_peer_state(&ev, server))) {
    perror("Could not allocate server state");
    return -1;
  }
  state_tmp->peer_kind = SERVER;
  PROP_ERR(epoll_ctl(epollfd, EPOLL_CTL_ADD, server, &ev));
  PROP_ERR(listen(server, 5));
  close(socket_not_listening);
  while (true) {
    struct epoll_event events[5];
    int nfds;

    PROP_ERR(nfds = epoll_wait(epollfd, events, ARR_LEN(events), -1));
    for (int n = 0; n < nfds; ++n) {
      peer_state_t *peer = peer_state(&events[n]);
      buf_ptr = printf_buf;
#define HAS_OUTPUT()                                                           \
  {                                                                            \
    events[n].events |= EPOLLOUT;                                              \
    epoll_ctl(epollfd, EPOLL_CTL_MOD, peer->fd, &events[n]);                   \
  }
      if (peer->peer_kind == SERVER) {
        int client, child_pid;
        PROP_ERR(client = accept(peer->fd, NULL, NULL));
        printf("New client %u\n", client);
        ev.events = EPOLLIN;
        if (!(state_tmp = malloc_client_state(&ev, client))) {
          close(client);
          continue;
        } else if (state_tmp->client_state.cred.uid != server_user ||
                   epoll_ctl(epollfd, EPOLL_CTL_ADD, client, &ev) == -1) {
          free(state_tmp);
          close(client);
          continue;
        }
      } else if (peer->peer_kind == CLIENT) {
        while (peer->client_state.write_buf != NULL) {
          write_buf_t *write_buf = peer->client_state.write_buf;
          if (write_buf->buf_kind == WRITE_BUF_CLOSE) {
            epoll_ctl(epollfd, EPOLL_CTL_DEL, peer->fd, &events[n]);
            close(peer->fd);
            if (peer->client_state.client_kind == HASHER_CLIENT) {
              close(peer->client_state.hash_fd);
            }
            close(peer->client_state.pid);
            free(peer);
            goto next_event;
          }
          int send_len =
              send_peer_msg(peer->fd, write_buf->info, write_buf->context,
                            write_buf->context_len, MSG_DONTWAIT);
          if (send_len == 0) {
            write_buf->buf_kind = WRITE_BUF_CLOSE;
            free_write_buf(write_buf->next);
          } else if (send_len > 0) {
            peer->client_state.write_buf = write_buf->next;
            write_buf->next = NULL;
            free_write_buf(write_buf);
          } else if (send_len == -1 &&
                     (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
          } else {
            perror("Send failed");
            break;
          }
        }
        if (peer->client_state.write_buf == NULL) {
          events[n].events = EPOLLIN;
          epoll_ctl(epollfd, EPOLL_CTL_MOD, peer->fd, &events[n]);
        }
        msg_info_t info;
        msg_context_t context[2];
        int fd;
        char buf[256];
        int c;
        int len;
        len = recv_peer_msg(peer->fd, &info, context);
        if (len == 0 || len == -1) {
          HAS_OUTPUT();
          write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
          b->buf_kind = WRITE_BUF_CLOSE;
          continue;
        }
        if (info.kind == MSG_HASH_DATA) {
          int secret_fd;
          fd = context[0].fd;
          if ((secret_fd = get_session_secret_fd()) == -1) {
            msg_info_t reply = {0};
            HAS_OUTPUT();
            write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
            reply.kind = MSG_NOT_AUTHENTICATED;
            b->info = reply;
            close(fd);
            continue;
          }
          if (info.data_len <= 0 || info.data_len > 1 << 30) {
            close(fd);
            fprintf(stderr, "Invalid file size received from peer: %i\n",
                    info.data_len);
            HAS_OUTPUT();
            write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
            b->buf_kind = WRITE_BUF_CLOSE;
            continue;
          }
          char *data = mmap(NULL, info.data_len, PROT_READ,
                            MAP_SHARED | MAP_POPULATE, fd, 0);
          close(fd);
          if (data == MAP_FAILED) {
            perror("Could not map secret");
            return -1;
          }
          if (peer->client_state.client_kind == NEW_CLIENT) {
            peer->client_state.client_kind = HASHER_CLIENT;
            PROP_ERR(peer->client_state.hash_fd = memfd_secret(O_CLOEXEC));
            PROP_ERR(hash_init_memfd(peer->client_state.hash_fd, secret_fd,
                                     (unsigned char *)data, info.data_len));
          } else if (peer->client_state.client_kind == HASHER_CLIENT) {
            PROP_ERR(hash_add(peer->client_state.hash_fd, (unsigned char *)data,
                              info.data_len));
          }
          PROP_ERR(munmap(data, info.data_len));
        } else if (info.kind == MSG_HASH_FINALIZE &&
                   peer->client_state.client_kind == HASHER_CLIENT) {
          int secret_fd;
          if ((secret_fd = get_session_secret_fd()) == -1) {
            HAS_OUTPUT();
            write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
            msg_info_t reply = {0};
            reply.kind = MSG_NOT_AUTHENTICATED;
            b->info = reply;
            b = new_write_buf(&peer->client_state.write_buf);
            b->buf_kind = WRITE_BUF_CLOSE;
            continue;
          }
          sha256_hash_t hash;
          PROP_ERR(finalize_hash(peer->client_state.hash_fd, secret_fd, &hash));
          close(peer->client_state.hash_fd);
          int result_fd;
          PROP_ERR(result_fd = memfd_secret(O_CLOEXEC));
          PROP_ERR(ftruncate(result_fd, sizeof(sha256_hash_hex_t)));
          sha256_hash_hex_t *result =
              mmap(NULL, sizeof(sha256_hash_hex_t), PROT_WRITE, MAP_SHARED,
                   result_fd, 0);
          if (result == MAP_FAILED) {
            close(result_fd);
            break;
          }
          *result = hash_to_hex(&hash);
          munmap(result, sizeof(sha256_hash_hex_t));
          HAS_OUTPUT();
          write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
          msg_info_t reply;
          reply.kind = MSG_HASH_FINALIZED;
          b->info = reply;
          b->context[0] = (msg_context_t){result_fd};
          b->context_len = 1;
          b->fds_to_close[0] = result_fd;
          b->num_fds_to_close = 1;
        } else if (info.kind == MSG_AUTHENTICATE &&
                   peer->client_state.client_kind == NEW_CLIENT) {
          char *auth_mem;
          if ((auth_mem = mmap(NULL, info.data_len, PROT_READ, MAP_SHARED,
                               context[0].fd, 0)) == MAP_FAILED) {
            close(context[0].fd);
            return -1;
          }
          close(context[0].fd);
          msg_info_t reply;
          if (authenticate_user(auth_mem, info.data_len) == 1) {
            reply.kind = MSG_AUTHENTICATED;
            peer->client_state.client_has_authenticated |= 1;
          } else {
            reply.kind = MSG_NOT_AUTHENTICATED;
          }
          munmap(auth_mem, info.data_len);
          HAS_OUTPUT();
          write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
          b->info = reply;
        } else if (info.kind == MSG_UPDATE_PASSWORD && peer->client_state.client_has_authenticated) {
          int secret_fd;
          if ((secret_fd = get_session_secret_fd()) == -1) {
            HAS_OUTPUT();
            write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
            msg_info_t reply = {0};
            reply.kind = MSG_NOT_AUTHENTICATED;
            b->info = reply;
            b = new_write_buf(&peer->client_state.write_buf);
            b->buf_kind = WRITE_BUF_CLOSE;
            close(context[0].fd);
          }
          char *pw_mem;
          if ((pw_mem = mmap(NULL, info.data_len, PROT_READ, MAP_SHARED, context[0].fd, 0)) == MAP_FAILED) {
              close(context[0].fd);
              return -1;
          }
          close(context[0].fd);
          int output_fd = memfd_create("new_persistent", 0);
          PROP_ERR(create_user_persistent_cred_secret(secret_fd, pw_mem, info.data_len, output_fd));
          int child_pid;
          PROP_ERR(child_pid = fork());
          if (child_pid == 0) {
              int auth_fd;
              PROP_ERR(auth_fd = inherit_fd(get_system_secret_fd()));
              PROP_ERR(output_fd = inherit_fd(output_fd));
              const char *update_arg = bufnprintf(&buf_ptr, buf_end, "replace_key=%i,auth_token=%i", output_fd, auth_fd);
              fprintf(stderr, "Running update with %s\n", update_arg);
              char *args[] = {"/usr/sbin/pam_secret", (char*)update_arg, NULL};
              if (execv(args[0], args) == -1) {
                  perror("Child process execve failed");
                  return -1;
              }
          } else {
              close(output_fd);
            int wstatus;
            waitpid(child_pid, &wstatus, 0);
            HAS_OUTPUT();
            write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
            msg_info_t reply = {0};
            reply.kind = MSG_UNKNOWN_ERROR;
            if (!WIFEXITED(wstatus)) {
              perror("Child process me crashed");
            } else if (WEXITSTATUS(wstatus) == 0) {
                reply.kind = MSG_UPDATE_PASSWORD_SUCCESS;
                continue;
            }
            b->info = reply;
            b = new_write_buf(&peer->client_state.write_buf);
            b->buf_kind = WRITE_BUF_CLOSE;
          }
        } else if (info.kind == MSG_CLEAR_SECRET &&
                   peer->client_state.client_kind == NEW_CLIENT) {
          lock_plain_user_secret();
          HAS_OUTPUT();
          write_buf_t *b = new_write_buf(&peer->client_state.write_buf);
          msg_info_t reply = {0};
          reply.kind = MSG_NOT_AUTHENTICATED;
          b->info = reply;
          b = new_write_buf(&peer->client_state.write_buf);
          b->buf_kind = WRITE_BUF_CLOSE;
        }
      }
    next_event:
    }
  }
}
