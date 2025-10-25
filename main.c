#include "creds.h"
#include "daemon.h"
#include "extern.h"
#include "fortify.h"
#include "hash.h"
#include "install.h"
#include "ipc.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
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

int main(int argc, char **argv) {
  assert_no_namespace();
  int c;
  const char *password = "test";
  int hash_fd = -1;
  int daemon_sock = -1;
#define SOCKET_CONNECT() { if (daemon_sock == -1) PROP_ERR(daemon_sock = connect_daemon()); }
  for (int arg = 1; arg < argc; ++arg) {
    uid_t user;
    int separator = -1;
    if (sscanf(argv[arg], "add_user=%u", &user) == 1) {
      setuid(user);
      if (getuid() != user) {
        fprintf(stderr, "You don't have permission to act for user %i\n", user);
        return EPERM;
      }
      // const char *password = getpass("Password for user: ");
      int password_len = strlen(password);
      if (password_len == 0) {
        fprintf(stderr, "Password not changed\n");
        return 0;
      }
      PROP_ERR(create_user_session_cred_secret(password, password_len));
    } else if (strcmp("install", argv[arg]) == 0) {
      PROP_ERR(install_persistent_credentials_directory());
    } else if (sscanf(argv[arg], "hmac=%n", &separator) == 0 &&
               separator != -1) {
      const char *msg = argv[arg] + separator;
      int msg_len = strlen(msg);
      if (hash_fd == -1) {
        PROP_ERR(hash_fd = memfd_secret(O_CLOEXEC));
        int secret;
        PROP_ERR(secret = get_session_secret_fd());
        PROP_ERR(
            hash_init_memfd(hash_fd, secret, (unsigned char *)msg, msg_len));
      } else {
        PROP_ERR(hash_add(hash_fd, (unsigned char*)msg, msg_len));
      }
    } else if (strcmp("print_hmac", argv[arg]) == 0) {
      sha256_hash_t hash;
      PROP_ERR(finalize_hash(hash_fd, get_session_secret_fd(), &hash));
      printf("Hashed to %s", hash_to_hex(&hash).printable);
    } else if (strcmp("auth", argv[arg]) == 0) {
      const char *password = getpass("Password: ");
      int password_len = strlen(password);
      if (password_len > 0) {
        if (authenticate_user(password, password_len) == 1) {
          auto secret = alloc_secret_state();
          free_secret_state(secret);
        }
      }
    } else if (strcmp("remote_auth", argv[arg]) == 0) {
        SOCKET_CONNECT();
      const char *password = getpass("Password: ");
      int pass_fd;
      int password_len = strlen(password);
      PROP_ERR(pass_fd = memfd_secret(O_CLOEXEC));
      PROP_ERR(ftruncate(pass_fd, password_len));
      char *password_out;
      if ((password_out = mmap(NULL, password_len, PROT_WRITE, MAP_SHARED, pass_fd, 0)) == MAP_FAILED) {
          perror("Could not map password\n");
          return -1;
      }
      memcpy(password_out, password, password_len);
      munmap(password_out, password_len);
      msg_info_t msg;
      msg_context_t context[2] = {pass_fd};
      msg.kind = MSG_AUTHENTICATE;
      msg.data_len = password_len;
      PROP_ERR(send_peer_msg(daemon_sock, msg, context, 1, 0));
      int len;
      msg_info_t info;
      PROP_ERR(len = recv_peer_msg(daemon_sock, &info, context));
      if (info.kind == MSG_NOT_AUTHENTICATED) {
          printf("Not authenticated\n");
          return -1;
      } else if (info.kind == MSG_AUTHENTICATED) {
          printf("Authenticated\n");
      }
    } else if (strcmp("lock", argv[arg]) == 0) {
      lock_plain_user_secret();
    } else if (strcmp("remote_lock", argv[arg]) == 0) {
      SOCKET_CONNECT();
      msg_info_t msg;
      msg.kind = MSG_CLEAR_SECRET;
      PROP_ERR(send_peer_msg(daemon_sock, msg, NULL, 0, 0));
    } else if (strcmp("daemon", argv[arg]) == 0) {
      run_daemon();
    } else if (sscanf(argv[arg], "send_file=%n", &separator) == 0 &&
               separator != -1) {
      char *filename = argv[arg] + separator;
      int file;
      int filesize;
      PROP_ERR(file = open(filename, O_CLOEXEC | O_RDONLY, 0));
      PROP_ERR(filesize = lseek(file, 0, SEEK_END));
      PROP_ERR(lseek(file, 0, SEEK_SET));
      SOCKET_CONNECT();
      msg_context_t context[] = {fd_to_context(file)};
      msg_info_t msg;
      msg.kind = MSG_HASH_DATA;
      msg.data_len = filesize;
      PROP_ERR(send_peer_msg(daemon_sock, msg, context, ARR_LEN(context), 0));
    } else if (sscanf(argv[arg], "send_secret=%n", &separator) == 0 &&
               separator != -1) {
        SOCKET_CONNECT();
      char *text = argv[arg] + separator;
      int text_len = strlen(text);
      int file;
      PROP_ERR(file = memfd_secret(O_CLOEXEC));
      PROP_ERR(ftruncate(file, text_len));
      char *secret = mmap(NULL, text_len, PROT_WRITE, MAP_SHARED, file, 0);
      if (secret == MAP_FAILED) {
        perror("Could not map secret");
        return -1;
      }
      memcpy(secret, text, text_len);
      PROP_ERR(munmap(secret, text_len));
      msg_info_t msg;
      msg.kind = MSG_HASH_DATA;
      msg.data_len = text_len;
      msg_context_t context[] = {fd_to_context(file)};
      PROP_ERR(send_peer_msg(daemon_sock, msg, context, ARR_LEN(context), 0));
    } else if (strcmp("fetch_hash", argv[arg]) == 0) {
        SOCKET_CONNECT();
      msg_info_t msg;
      msg.kind = MSG_HASH_FINALIZE;
      PROP_ERR(send_peer_msg(daemon_sock, msg, NULL, 0, 0));
      int len;
      msg_info_t info;
      msg_context_t context[2];
      PROP_ERR(len = recv_peer_msg(daemon_sock, &info, context));
      if (info.kind == MSG_NOT_AUTHENTICATED) {
          printf("Not authenticated");
      } else if (info.kind == MSG_HASH_FINALIZED) {
          sha256_hash_hex_t *mem = mmap(NULL, sizeof(sha256_hash_hex_t), PROT_READ, MAP_SHARED, context[0].fd, 0);
          if (mem == MAP_FAILED) {
              perror("Could not map reply");
              return -1;
          }
          printf("%s\n", mem->printable);
          munmap(mem, sizeof(sha256_hash_hex_t));
      }
    } else {
        fprintf(stderr, "Unknown command %s\n", argv[arg]);
        return -1;
    }
  }
  return 0;
}
