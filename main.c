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
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

int install_new_user_key(int parent_auth_fd, int new_content) {
  fprintf(stderr, "Trying to install new user, gaining privileges");
  PROP_ERR(gain_root_privileges());
  int system_secret_fd;
  struct stat system_secret_stat, auth_token_stat;
  PROP_ERR(fstat(parent_auth_fd, &auth_token_stat));
  PROP_ERR(system_secret_fd = get_system_secret_fd());
  PROP_ERR(fstat(system_secret_fd, &system_secret_stat));
  fprintf(stderr, "Checking auth fd\n");
  if (system_secret_stat.st_dev != auth_token_stat.st_dev ||
      system_secret_stat.st_ino != auth_token_stat.st_ino) {
    errno = EACCES;
    return -1;
  }
  fprintf(stderr, "Installing new credential\n");
  PROP_ERR(install_user_session_cred_secret(new_content));
  fprintf(stderr, "Finalizing\n");
  PROP_ERR(drop_root_privileges(0));
  return 0;
}

int lib_main(int argc, char **argv) {
  if (argc == 2 && strcmp("install", argv[1]) == 0) {
    PROP_ERR(install_persistent_credentials_directory());
    PROP_ERR(maybe_create_system_secret());
    return 0;
  }
  {
    int auth_fd, source_fd, bytes_read = 0;
    if (argc == 2 &&
        sscanf(argv[1], "replace_key=%i,auth_token=%i%n", &source_fd, &auth_fd,
               &bytes_read) == 2 &&
        argv[1][bytes_read] == 0) {
      return install_new_user_key(auth_fd, source_fd);
    }
  }
  init_privileged();
  assert_no_namespace();
  int c;
  const char *password = "test";
  int hash_fd = -1;
  int daemon_sock = -1;
#define SOCKET_CONNECT()                                                       \
  {                                                                            \
    if (daemon_sock == -1)                                                     \
      PROP_ERR(daemon_sock = connect_daemon());                                \
  }
  for (int arg = 1; arg < argc; ++arg) {
    uid_t user;
    int separator = -1;
    if (strcmp("create_secret", argv[arg]) == 0) {
      const char *password = getpass("Password for user: ");
      int password_len = strlen(password);
      if (password_len == 0) {
        fprintf(stderr, "Aborted\n");
        return 0;
      }
      const char *filename = get_uid_session_cred_persistant_path(getuid());
      int new_fd;
      int result;
      int dir_fd;
      PROP_ERR(dir_fd = open(".", O_DIRECTORY, 0));
      PROP_ERR(new_fd = openat(dir_fd, ".", O_RDWR | O_TMPFILE,
                               0600));
      if ((result = create_user_persistent_cred_secret(
               -1, password, password_len, new_fd)) == -1) {
        perror("Could not create session");
      }
      char memfile_path[256];
      snprintf(memfile_path, ARR_LEN(memfile_path), "/proc/self/fd/%i", new_fd);
      linkat(AT_FDCWD, memfile_path, dir_fd, filename, AT_SYMLINK_FOLLOW);
      close(new_fd);
      close(dir_fd);
      return result == -1 ? 1 : 0;
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
        PROP_ERR(hash_add(hash_fd, (unsigned char *)msg, msg_len));
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
      if ((password_out = mmap(NULL, password_len, PROT_WRITE, MAP_SHARED,
                               pass_fd, 0)) == MAP_FAILED) {
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
      int child_pid;
      int socket_up_indicator[2];
      PROP_ERR(pipe2(socket_up_indicator, 0));
      PROP_ERR(child_pid = fork());
      if (child_pid != 0) {
        char buf[32];
        close(socket_up_indicator[PIPE_TX]);
        read(socket_up_indicator[PIPE_RX], buf, ARR_LEN(buf));
        exit(EXIT_SUCCESS);
      }
      PROP_ERR(setsid());
      signal(SIGHUP, SIG_IGN);
      PROP_ERR(child_pid = fork());
      if (child_pid != 0)
        exit(EXIT_SUCCESS);
      close(socket_up_indicator[PIPE_RX]);
      run_daemon(socket_up_indicator[PIPE_TX]);
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
        sha256_hash_hex_t *mem = mmap(NULL, sizeof(sha256_hash_hex_t),
                                      PROT_READ, MAP_SHARED, context[0].fd, 0);
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
