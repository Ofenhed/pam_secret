#include "daemon.h"
#include "creds.h"
#include "extern.h"
#include "hash.h"
#include "ipc.h"
#include "log.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

int connect_daemon(uid_t(get_target_user)()) {
  int sock;
  struct sockaddr_un address;
  if (snprintf(address.sun_path, ARR_LEN(address.sun_path), "%s/%s",
               get_runtime_dir(get_target_user),
               get_socket_name()) >= ARR_LEN(address.sun_path)) {
    CRITICAL_ERR("Socket path too long");
  }
  address.sun_family = AF_UNIX;
  if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
    return -1;
  if (connect(sock, (struct sockaddr *)&address, sizeof(address)) == -1)
    return -1;
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
  signal(SIGPIPE, SIG_IGN);
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
    hash_state_t *hash_state;
  };
  // TODO: Writing, write buffer and events?
} client_state_t;

typedef struct {
  enum {
    SERVER = 1,
    CLIENT,
    HASH_FORK,
    INOTIFY_TRIGGER,
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

int run_daemon(const char *name, int socket_not_listening) {
  char printf_buf[256];
  char *buf_ptr = printf_buf;
#define RESET_BUF_PTR() (buf_ptr = printf_buf)
  int persistent_inotify, inotify_key_deleted, inotify_run_dir_modified;
  const char *const buf_end = ARR_END(printf_buf);
  peer_state_t *state_tmp;
  uid_t server_user = geteuid();

  int epollfd, server_shutdown = 0;
  struct epoll_event ev;

  PROP_CRIT(epollfd = epoll_create1(O_CLOEXEC));

  {
    PROP_CRIT(persistent_inotify = inotify_init1(IN_CLOEXEC));
    const char *path = bufnprintf(&buf_ptr, buf_end, "%s/%s",
                                  get_persistent_storage_location(),
                                  get_persistent_secret_filename(geteuid()));
    PROP_CRIT(inotify_key_deleted = inotify_add_watch(
                  persistent_inotify, path,
                  IN_DELETE_SELF | IN_MOVE_SELF | IN_ONESHOT));
    RESET_BUF_PTR();
    ev.events = EPOLLIN;
    if (!(state_tmp = malloc_peer_state(&ev, persistent_inotify))) {
      perror("Couldn't allocate inotify state");
      return -1;
    }
    state_tmp->peer_kind = INOTIFY_TRIGGER;
    PROP_CRIT(epoll_ctl(epollfd, EPOLL_CTL_ADD, persistent_inotify, &ev));
  }

  struct sockaddr_un address;
  address.sun_family = AF_UNIX;
  const char *const socket_dir = get_runtime_dir(geteuid);
  const char *const socket_name = get_socket_name();
  if (snprintf(address.sun_path, ARR_LEN(address.sun_path), "%s/%s", socket_dir,
               socket_name) >= ARR_LEN(address.sun_path)) {
    CRITICAL_ERR("Socket path too long");
  }
  unlink(address.sun_path);
  int umask_before = umask(~0600);
  int server = socket(AF_UNIX, SOCK_STREAM, 0);
  PROP_CRIT(fcntl(server, F_SETFD, FD_CLOEXEC));
  PROP_CRIT(bind(server, (struct sockaddr *)(&address), sizeof(address)));
  PROP_CRIT(inotify_run_dir_modified = inotify_add_watch(
                persistent_inotify, socket_dir, IN_DELETE | IN_CREATE));
  umask(umask_before);
  ev.events = EPOLLIN;
  if (!(state_tmp = malloc_peer_state(&ev, server))) {
    perror("Could not allocate server state");
    return -1;
  }
  state_tmp->peer_kind = SERVER;
  PROP_CRIT(epoll_ctl(epollfd, EPOLL_CTL_ADD, server, &ev));
  PROP_CRIT(listen(server, 5));
  if (socket_not_listening != -1)
    close(socket_not_listening);
  while (true) {
    struct epoll_event events[5];
    int nfds;

    PROP_CRIT(nfds = epoll_wait(epollfd, events, ARR_LEN(events),
                                server_shutdown ? 3000 : -1));
    if (server_shutdown && !nfds) {
      log_debug("I feel ready now. Take me.");
      exit(0);
    }
    for (int n = 0; n < nfds; ++n) {
      peer_state_t *peer = peer_state(&events[n]);
      write_buf_t *b;
      RESET_BUF_PTR();
      log_debug("Event from fd %i\n", peer->fd);
#define HAS_OUTPUT()                                                           \
  {                                                                            \
    events[n].events |= EPOLLOUT;                                              \
    epoll_ctl(epollfd, EPOLL_CTL_MOD, peer->fd, &events[n]);                   \
  }
      if (peer->peer_kind == SERVER) {
        int client;
        PROP_CRIT(client = accept4(peer->fd, NULL, NULL, SOCK_CLOEXEC));
        log_debug("New client %u\n", client);
        ev.events = EPOLLIN;
        if (!(state_tmp = malloc_client_state(&ev, client))) {
          log_error("Failed to allocate client state\n");
          close(client);
          continue;
        } else if ((state_tmp->client_state.cred.uid & ~server_user) ||
                   epoll_ctl(epollfd, EPOLL_CTL_ADD, client, &ev) == -1) {
          log_error("Invalid user? %i\n", state_tmp->client_state.cred.uid);
          free(state_tmp);
          close(client);
          continue;
        }
      } else if (peer->peer_kind == INOTIFY_TRIGGER) {
        char iev_buf[(sizeof(struct inotify_event) + 128) << 3];
        int c;
        PROP_CRIT(c = read(persistent_inotify, &iev_buf, ARR_LEN(iev_buf)));
        if (c == 0) {
          log_error("Inotify closed, what does that mean?\n");
          return -1;
        }
        struct inotify_event *iev_ptr = (struct inotify_event *)iev_buf;
        const struct inotify_event *iev_end =
            (struct inotify_event *)(iev_buf + c);
        while (iev_ptr < iev_end) {
          if (iev_ptr->wd == inotify_key_deleted) {
            log_warning(
                "User key deleted!\nThat's someone else's problem now.\n");
            epoll_ctl(epollfd, EPOLL_CTL_DEL, server, &events[n]);
            close(server);
            if (fork() == 0) {
              char *args[] = {(char *)name, "daemon", NULL};
              execv("/proc/self/exe", args);
              exit(EXIT_FAILURE);
            }
            server_shutdown = 1;
          } else if (iev_ptr->wd == inotify_run_dir_modified &&
                     strcmp(iev_ptr->name, socket_name) == 0) {
            log_error("They killed my socket file.\nWait for me, buddy...\n");
            epoll_ctl(epollfd, EPOLL_CTL_DEL, server, &events[n]);
            close(server);
            server_shutdown = 1;
          }
          iev_ptr += sizeof(struct inotify_event) + iev_ptr->len;
        }
      } else if (peer->peer_kind == CLIENT) {
        while (peer->client_state.write_buf != NULL) {
          write_buf_t *write_buf = peer->client_state.write_buf;
          if (write_buf->buf_kind == WRITE_BUF_CLOSE) {
            epoll_ctl(epollfd, EPOLL_CTL_DEL, peer->fd, &events[n]);
            close(peer->fd);
            if (peer->client_state.client_kind == HASHER_CLIENT) {
              crit_munmap(peer->client_state.hash_state);
            }
            close(peer->client_state.pid);
            free(peer);
            goto next_event;
          }
          int send_len = send_peer_msg(
              peer->fd, write_buf->info, write_buf->context,
              write_buf->context_len, MSG_DONTWAIT | MSG_NOSIGNAL);
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
          } else if (send_len == -1 && errno == EPIPE) {
            free_write_buf(peer->client_state.write_buf);
            peer->client_state.write_buf = NULL;
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              b->buf_kind = WRITE_BUF_CLOSE;
            }
            break;
          } else {
            perror("Send failed");
            break;
          }
        }
        if (peer->client_state.write_buf == NULL &&
            events[n].events & EPOLLOUT) {
          events[n].events = EPOLLIN;
          epoll_ctl(epollfd, EPOLL_CTL_MOD, peer->fd, &events[n]);
        }
        if (server_shutdown && events[n].events & EPOLLIN) {
          events[n].events = EPOLLOUT;
          if ((b = new_write_buf(&peer->client_state.write_buf))) {
            HAS_OUTPUT();
            b->buf_kind = WRITE_BUF_CLOSE;
          }
        }
        msg_info_t info;
        msg_context_t context[2];
        int fd;
        int len;
        len = recv_peer_msg(peer->fd, &info, context);
        if (len == 0 || len == -1) {
          log_debug("Connection failed or closed\n");
          if ((b = new_write_buf(&peer->client_state.write_buf))) {
            HAS_OUTPUT();
            b->buf_kind = WRITE_BUF_CLOSE;
          }
          continue;
        }
        if (info.kind == MSG_HASH_DATA) {
          fd = context[0].fd;
          if (info.data_len < 0 || info.data_len > 1 << 30) {
            close(fd);
            log_debug("Invalid file size received from peer: %i",
                      info.data_len);
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              b->buf_kind = WRITE_BUF_CLOSE;
            }
            continue;
          }
          unsigned char *data = NULL;
          if (info.data_len > 0) {
            data = crit_mmap(NULL, info.data_len, PROT_READ,
                             MAP_SHARED | MAP_POPULATE, fd, 0);
          }
          close(fd);
          if (peer->client_state.client_kind == NEW_CLIENT) {
            secret_state_t *session_secret;
            if (!(session_secret = map_session_cred())) {
              if ((b = new_write_buf(&peer->client_state.write_buf))) {
                msg_info_t reply = {0};
                HAS_OUTPUT();
                reply.kind = MSG_NOT_AUTHENTICATED;
                b->info = reply;
              }
              close(fd);
              continue;
            }
            peer->client_state.client_kind = HASHER_CLIENT;
            crit_memfd_secret_alloc(peer->client_state.hash_state);
            secret_state_t *system_secret =
                crit_mmap(NULL, sizeof(*system_secret), PROT_READ, MAP_SHARED,
                          get_system_secret_fd(), 0);
            if (peer->client_state.client_has_authenticated) {
              hmac(peer->client_state.hash_state,
                   HASH_TYPE_AUTHENTICATED_HMAC_REQUEST,
                   STR_LEN(HASH_TYPE_AUTHENTICATED_HMAC_REQUEST),
                   (unsigned char *)session_secret, sizeof(*session_secret));
            } else {
              hmac(peer->client_state.hash_state, HASH_TYPE_HMAC_REQUEST,
                   STR_LEN(HASH_TYPE_HMAC_REQUEST),
                   (unsigned char *)session_secret, sizeof(*session_secret));
            }
            crit_munmap(session_secret);
            hmac_msg(peer->client_state.hash_state,
                     (unsigned char *)system_secret, sizeof(*system_secret));
            crit_munmap(system_secret);
            hmac_msg(peer->client_state.hash_state, data, info.data_len);
          } else if (peer->client_state.client_kind == HASHER_CLIENT) {
            hmac_msg(peer->client_state.hash_state, data, info.data_len);
          }
          if (data != NULL) {
            PROP_CRIT(munmap(data, info.data_len));
          }
        } else if (info.kind == MSG_HASH_FINALIZE &&
                   peer->client_state.client_kind == HASHER_CLIENT) {
          secret_state_t *session_secret;
          if (!(session_secret = map_session_cred())) {
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              msg_info_t reply = {0};
              reply.kind = MSG_NOT_AUTHENTICATED;
              b->info = reply;
              if ((b = new_write_buf(&peer->client_state.write_buf))) {
                b->buf_kind = WRITE_BUF_CLOSE;
              }
            }
            continue;
          }
          hmac_msg(peer->client_state.hash_state,
                   (unsigned char *)session_secret, sizeof(*session_secret));
          crit_munmap(session_secret);
          int result_fd;
          PROP_CRIT(result_fd = memfd_secret(O_CLOEXEC));
          PROP_CRIT(ftruncate(result_fd, sizeof(sha256_hash_t)));
          sha256_hash_t *result =
              crit_mmap(NULL, sizeof(sha256_hash_t), PROT_WRITE, MAP_SHARED,
                        result_fd, 0);
          hmac_finalize(peer->client_state.hash_state, result);
          crit_munmap(peer->client_state.hash_state);
          crit_munmap(result);
          if ((b = new_write_buf(&peer->client_state.write_buf))) {
            HAS_OUTPUT();
            msg_info_t reply;
            reply.kind = MSG_HASH_FINALIZED;
            b->info = reply;
            b->context[0] = (msg_context_t){{result_fd}};
            b->context_len = 1;
            b->fds_to_close[0] = result_fd;
            b->num_fds_to_close = 1;
          }
        } else if (info.kind == MSG_AUTHENTICATE &&
                   peer->client_state.client_kind == NEW_CLIENT) {
          log_debug("Received authentication attempt from %i\n", peer->fd);
          unsigned char *auth_mem;
          if (info.data_len <= 0 || info.data_len > MAX_PASSWORD_LENGTH) {
            log_debug("Illegal data length from peer: %i", info.data_len);
            close(context[0].fd);
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              b->buf_kind = WRITE_BUF_CLOSE;
              continue;
            }
          }
          if ((auth_mem = mmap(NULL, info.data_len, PROT_READ, MAP_SHARED,
                               context[0].fd, 0)) == MAP_FAILED) {
            log_debug("Got invalid file descriptor from peer");
            close(context[0].fd);
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              b->buf_kind = WRITE_BUF_CLOSE;
            }
            continue;
          }
          close(context[0].fd);
          msg_info_t reply = {0};
          if (authenticate_user(auth_mem, info.data_len) == 1) {
            log_debug("Creating reply\n");
            reply.kind = MSG_AUTHENTICATED;
            int auth_token_fd;
            PROP_CRIT(auth_token_fd = memfd_secret(O_CLOEXEC));
            PROP_CRIT(ftruncate(auth_token_fd, sizeof(sha256_hash_t)));
            sha256_hash_t *auth_token =
                crit_mmap(NULL, sizeof(*auth_token), PROT_WRITE, MAP_SHARED,
                          auth_token_fd, 0);
            if (pam_translated_user_auth_token(auth_mem, info.data_len,
                                               auth_token) != -1 &&
                (b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              b->info = reply;
              b->context[0] =
                  (msg_context_t){{b->fds_to_close[0] = auth_token_fd}};
              b->context_len = b->num_fds_to_close = 1;
            }
            crit_munmap(auth_token);
            peer->client_state.client_has_authenticated |= 1;
          } else {
            reply.kind = MSG_NOT_AUTHENTICATED;
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              b->info = reply;
            }
          }
          munmap(auth_mem, info.data_len);
#ifdef DEBUG_QUERY_SECRETS
        } else if (info.kind == MSG_DUMP_SECRET) {
          char *mapped;
          if ((mapped = mmap(NULL, 512, PROT_READ, MAP_SHARED, info.secret_fd,
                             0)) != MAP_FAILED) {
            printf("Secret %u:\n%512s\n", info.secret_fd, mapped);
            munmap(mapped, 512);
          }
#endif
        } else if (info.kind == MSG_UPDATE_PASSWORD) {
          int secret_fd;
          if (!peer->client_state.client_has_authenticated ||
              (secret_fd = get_session_secret_fd()) == -1 ||
              info.data_len <= 0 || info.data_len > MAX_PASSWORD_LENGTH) {
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              msg_info_t reply = {0};
              reply.kind = MSG_NOT_AUTHENTICATED;
              b->info = reply;
            }
            close(context[0].fd);
            continue;
          }
          unsigned char *pw_mem = crit_mmap(NULL, info.data_len, PROT_READ,
                                            MAP_SHARED, context[0].fd, 0);
          close(context[0].fd);
          int auth_token_fd;
          {
            PROP_CRIT(auth_token_fd = memfd_secret(O_CLOEXEC));
            PROP_CRIT(ftruncate(auth_token_fd, sizeof(sha256_hash_t)));
            sha256_hash_t *auth_token =
                crit_mmap(NULL, sizeof(*auth_token), PROT_WRITE, MAP_SHARED,
                          auth_token_fd, 0);
            PROP_CRIT(pam_translated_user_auth_token(pw_mem, info.data_len,
                                                     auth_token));
            crit_munmap(auth_token);
          }
          int output_fd = memfd_create("new_persistent", 0);
          PROP_CRIT(create_user_persistent_cred_secret(
              secret_fd, pw_mem, info.data_len, output_fd));
          crit_munmap(pw_mem);
          int child_pid;
          PROP_CRIT(child_pid = fork());
          if (child_pid == 0) {
            int auth_fd;
            PROP_CRIT(auth_fd = inherit_fd(get_system_secret_fd()));
            PROP_CRIT(output_fd = inherit_fd(output_fd));
            const char *update_arg =
                bufnprintf(&buf_ptr, buf_end, REPLACE_KEY_CMD_FORMAT, output_fd,
                           auth_fd, NULL);
            log_debug("Running update with %s\n", update_arg);
            char *args[] = {"/usr/sbin/pam_secret", (char *)update_arg, NULL};
            if (execv(args[0], args) == -1) {
              perror("Child process execve failed");
              return -1;
            }
          } else {
            close(output_fd);
            int wstatus;
            waitpid(child_pid, &wstatus, 0);
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              HAS_OUTPUT();
              msg_info_t reply = {0};
              reply.kind = MSG_UNKNOWN_ERROR;
              if (!WIFEXITED(wstatus)) {
                perror("Child process me crashed");
              } else if (WEXITSTATUS(wstatus) == 0) {
                reply.kind = MSG_UPDATE_PASSWORD_SUCCESS;
                b->info = reply;
                b->context[0] =
                    (msg_context_t){{b->fds_to_close[0] = auth_token_fd}};
                b->context_len = b->num_fds_to_close = 1;
                continue;
              } else {
                reply.kind = MSG_UNKNOWN_ERROR;
              }
              b->info = reply;
            }
            if ((b = new_write_buf(&peer->client_state.write_buf))) {
              b->buf_kind = WRITE_BUF_CLOSE;
            }
          }
        } else if (info.kind == MSG_CLEAR_SECRET &&
                   peer->client_state.client_kind == NEW_CLIENT) {
          lock_plain_user_secret();
          if ((b = new_write_buf(&peer->client_state.write_buf))) {
            HAS_OUTPUT();
            msg_info_t reply = {0};
            reply.kind = MSG_NOT_AUTHENTICATED;
            b->info = reply;
            b = new_write_buf(&peer->client_state.write_buf);
            b->buf_kind = WRITE_BUF_CLOSE;
          }
        }
      }
    next_event:
    }
  }
}
