#include "creds.h"
#include "daemon.h"
#include "extern.h"
#include "fortify.h"
#include "hash.h"
#include "install.h"
#include "ipc.h"
#include "log.h"
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
#include <unistd.h>

#define MAX_PASSWORD_LENGTH 64

int install_new_user_key(int parent_auth_fd, int new_content) {
  log_debug("Trying to install new user, gaining privileges");
  PROP_ERR(gain_root_privileges());
  int system_secret_fd;
  struct stat system_secret_stat, auth_token_stat;
  PROP_ERR(fstat(parent_auth_fd, &auth_token_stat));
  PROP_ERR(system_secret_fd = get_system_secret_fd());
  if (system_secret_fd == parent_auth_fd) {
    log_error("Clever...");
    errno = EINVAL;
    return -1;
  }
  PROP_ERR(fstat(system_secret_fd, &system_secret_stat));
  log_debug("Checking auth fd");
  if (system_secret_stat.st_dev != auth_token_stat.st_dev ||
      system_secret_stat.st_ino != auth_token_stat.st_ino) {
    errno = EACCES;
    return -1;
  }
  // TODO; Check if something like this is required. It shouldn't be, since the
  // parent directory is readable only by root.
  // log_debug("Making sure the auth fd is accessible");
  // int flags;
  // if (!((flags = fcntl(parent_auth_fd, F_GETFL)) & (O_RDONLY | O_RDWR |
  // O_WRONLY))) {
  //    log_debug("File descriptor was in mode %x, want one masked with %x\n",
  //    flags, (O_RDONLY | O_RDWR | O_WRONLY));
  //  errno = EACCES;
  //  return -1;
  //}
  log_debug("Installing new credential");
  // TODO: Figure out why install_user_session_cred_secret borks
  PROP_ERR(install_user_session_cred_secret(new_content, geteuid(), false));
  log_debug("Finalizing");
  PROP_ERR(drop_root_privileges(0));
  return 0;
}

EXPORTED int libpam_secret_exported_main(int argc, char **argv) {
  int hashed = 0;
  if (argc == 2 && strcmp("install", argv[1]) == 0) {
    PROP_ERR(install_persistent_credentials_directory());
    PROP_ERR(maybe_create_system_secret());
    return 0;
  }

  {
    int auth_fd, source_fd, bytes_read = 0;
    if (argc == 2 &&
        sscanf(argv[1], REPLACE_KEY_CMD_FORMAT "%n", &source_fd, &auth_fd,
               &bytes_read) == 2 &&
        argv[1][bytes_read] == 0) {
      return install_new_user_key(auth_fd, source_fd);
    }
  }
  init_privileged();
  assert_no_namespace();
  int daemon_sock = -1;
#ifdef DEBUG_QUERY_SECRETS
  int tmp_fd;
#endif
#define SOCKET_CONNECT()                                                       \
  {                                                                            \
    if (daemon_sock == -1 && (daemon_sock = connect_daemon(geteuid)) == -1) {  \
      CRITICAL_ERR("No running daemon found");                                 \
    }                                                                          \
  }
  for (int arg = 1; arg < argc; ++arg) {
    int separator = -1;
    if (strcmp("create_secret", argv[arg]) == 0) {
      if (get_persistent_secret_fd(geteuid()) != -1) {
        fputs("You already have a user credential installed.\nPlease contact "
              "an administrator to reset your credential.\n",
              stderr);
        exit(EXIT_FAILURE);
      }
      char *password[MAX_PASSWORD_LENGTH],
          *verify_password[MAX_PASSWORD_LENGTH];
      int secret_fd;
      PROP_CRIT(secret_fd = open(get_runtime_dir(geteuid), O_TMPFILE | O_RDWR));
      crit_memfd_secret_alloc(*password);
      crit_memfd_secret_alloc(*verify_password);
      int password_len;
      PROP_CRIT(password_len = read_secret_password(
                    *password, ARR_LEN(password), "New password: "));
      PROP_CRIT(read_secret_password(*verify_password, ARR_LEN(verify_password),
                                     "Verify password: "));
      if (strcmp(*password, *verify_password) != 0) {
        fprintf(stderr, "Passwords didn't match\n");
        return EXIT_FAILURE;
      }
      if (password_len == 0) {
        fprintf(stderr, "Aborted\n");
        return 0;
      }
      int cred_len;
      if ((cred_len = create_user_persistent_cred_secret(
               -1, (unsigned char *)*password, password_len, secret_fd)) ==
          -1) {
        perror("Could not create session");
        return -1;
      }
      crit_munmap(*password);
      char arg_buf[256];
      char *arg_ptr = arg_buf;
      const char *const arg_buf_end = ARR_END(arg_buf);
      int auth_fd = inherit_fd(get_system_secret_fd());
      int user_cred = inherit_fd(secret_fd);
      char *install_secret_arg = (char *)bufnprintf(
          &arg_ptr, arg_buf_end, REPLACE_KEY_CMD_FORMAT, user_cred, auth_fd);
      char *args[] = {argv[0], install_secret_arg, NULL};
      return execv("/proc/self/exe", args);
      return 0;
    } else if (strcmp("auth", argv[arg]) == 0) {
      SOCKET_CONNECT();
      int pass_fd;
      char *password;
      PROP_ERR(pass_fd = memfd_secret(O_CLOEXEC));
      DEFER({ close(pass_fd); });
      PROP_ERR(ftruncate(pass_fd, MAX_PASSWORD_LENGTH));
      password = crit_mmap(NULL, MAX_PASSWORD_LENGTH, PROT_READ | PROT_WRITE,
                           MAP_SHARED, pass_fd, 0);
      DEFER({ munmap(password, MAX_PASSWORD_LENGTH); });
      int password_len =
          read_secret_password(password, MAX_PASSWORD_LENGTH, "Password: ");
      msg_info_t msg;
      msg.kind = MSG_AUTHENTICATE;
      msg.data_len = password_len;
      PROP_ERR(send_peer_msg(daemon_sock, msg, &pass_fd, 0));
      int len;
      int auth_fd;
      PROP_ERR(len = recv_peer_msg(daemon_sock, &msg, &auth_fd));
      if (msg.kind == MSG_NOT_AUTHENTICATED) {
        fprintf(stderr, "Not authenticated\n");
        return -1;
      } else if (msg.kind == MSG_AUTHENTICATED) {
        close(auth_fd);
      }
#ifdef DEBUG_QUERY_SECRETS
    } else if (sscanf(argv[arg], "dump_secret=%u%n", &tmp_fd, &separator) ==
                   1 &&
               separator != -1) {
      SOCKET_CONNECT();
      msg_info_t msg;
      msg.kind = MSG_DUMP_SECRET;
      msg.secret_fd = tmp_fd;
      PROP_ERR(send_peer_msg(daemon_sock, msg, NULL, 0, 0));
#endif
    } else if (strcmp("passwd", argv[arg]) == 0) {
      SOCKET_CONNECT();
      const char *password = getpass("New password: ");
      int pass_fd;
      size_t password_len = strlen(password);
      PROP_ERR(pass_fd = memfd_secret(O_CLOEXEC));
      DEFER({ close(pass_fd); });
      PROP_ERR(ftruncate(pass_fd, password_len));
      if (password_len > 0) {
        char *password_out =
            crit_mmap(NULL, password_len, PROT_WRITE, MAP_SHARED, pass_fd, 0);
        DEFER({ munmap(password_out, password_len); });
        memcpy(password_out, password, password_len);
      }
      msg_info_t msg;
      msg.kind = MSG_UPDATE_PASSWORD;
      msg.data_len = password_len;
      PROP_ERR(send_peer_msg(daemon_sock, msg, &pass_fd, 0));
      int len;
      msg_info_t info;
      int auth_fd;
      PROP_ERR(len = recv_peer_msg(daemon_sock, &info, &auth_fd));
      if (info.kind == MSG_UPDATE_PASSWORD_SUCCESS) {
        close(auth_fd);
        log_info("Password updated\n");
        return 0;
      } else if (info.kind == MSG_AUTHENTICATED) {
        close(auth_fd);
        log_info("Authenticated\n");
      }
    } else if (strcmp("lock", argv[arg]) == 0) {
      SOCKET_CONNECT();
      msg_info_t msg;
      msg.kind = MSG_CLEAR_SECRET;
      PROP_ERR(send_peer_msg(daemon_sock, msg, NULL, 0));
    } else if (strcmp("daemon", argv[arg]) == 0) {
      int next = arg + 1;
      int socket_up_indicator[2] = {-1, -1};
      if (!(argc > next && strcmp("nofork", argv[next]) == 0)) {
        int child_pid;
        PROP_ERR(pipe2(socket_up_indicator, 0));
        PROP_ERR(child_pid = fork());
        if (child_pid != 0) {
          char buf[32];
          close(socket_up_indicator[PIPE_TX]);
          read(socket_up_indicator[PIPE_RX], buf, ARR_LEN(buf));
          close(socket_up_indicator[PIPE_RX]);
          continue;
        }
        PROP_ERR(setsid());
        signal(SIGHUP, SIG_IGN);
        PROP_ERR(child_pid = fork());
        if (child_pid != 0)
          exit(EXIT_SUCCESS);
        close(socket_up_indicator[PIPE_RX]);
      }
      run_daemon(argc > 0 ? argv[0] : "pam_secret",
                 socket_up_indicator[PIPE_TX]);
    } else if ((sscanf(argv[arg], "f=%n", &separator) == 0 &&
                separator != -1) ||
               (sscanf(argv[arg], "file=%n", &separator) == 0 &&
                separator != -1)) {
      ++hashed;
      char *filename = argv[arg] + separator;
      int file;
      int filesize;
      PROP_ERR(file = open(filename, O_CLOEXEC | O_RDONLY, 0));
      DEFER({ close(file); });
      PROP_ERR(filesize = lseek(file, 0, SEEK_END));
      PROP_ERR(lseek(file, 0, SEEK_SET));
      SOCKET_CONNECT();
      msg_info_t msg;
      msg.kind = MSG_HASH_DATA;
      msg.data_len = filesize;
      PROP_ERR(send_peer_msg(daemon_sock, msg, &file, 0));
    } else if ((sscanf(argv[arg], "s=%n", &separator) == 0 &&
                separator != -1) ||
               (sscanf(argv[arg], "str=%n", &separator) == 0 &&
                separator != -1) ||
               (sscanf(argv[arg], "string=%n", &separator) == 0 &&
                separator != -1) ||
               (sscanf(argv[arg], "text=%n", &separator) == 0 &&
                separator != -1) ||
               (sscanf(argv[arg], "txt=%n", &separator) == 0 &&
                separator != -1) ||
               (sscanf(argv[arg], "t=%n", &separator) == 0 &&
                separator != -1)) {
      ++hashed;
      SOCKET_CONNECT();
      char *text = argv[arg] + separator;
      size_t text_len = strlen(text);
      int file;
      PROP_ERR(file = memfd_secret(O_CLOEXEC));
      DEFER({ close(file); });
      PROP_ERR(ftruncate(file, text_len));
      if (text_len > 0) {
        char *secret =
            crit_mmap(NULL, text_len, PROT_WRITE, MAP_SHARED, file, 0);
        DEFER({ munmap(secret, text_len); });
        memcpy(secret, text, text_len);
      }
      msg_info_t msg;
      msg.kind = MSG_HASH_DATA;
      msg.data_len = text_len;
      PROP_ERR(send_peer_msg(daemon_sock, msg, &file, 0));
    } else {
      fprintf(stderr, "Unknown command %s\n", argv[arg]);
      return -1;
    }
  }
  if (hashed) {
    msg_info_t msg;
    msg.kind = MSG_HASH_FINALIZE;
    PROP_ERR(send_peer_msg(daemon_sock, msg, NULL, 0));
    int len;
    msg_info_t info;
    int hashed_fd;
    PROP_ERR(len = recv_peer_msg(daemon_sock, &info, &hashed_fd));
    if (info.kind == MSG_NOT_AUTHENTICATED) {
      fprintf(stderr, "Not authenticated\n");
      return EACCES;
    } else if (info.kind == MSG_HASH_FINALIZED) {

      sha256_hash_t *mem = crit_mmap(NULL, sizeof(sha256_hash_t), PROT_READ,
                                     MAP_SHARED, hashed_fd, 0);
      sha256_hash_hex_t hash = hash_to_hex(mem);
      crit_munmap(mem);
      printf("%s%s", hash.printable, isatty(1) ? "\n" : "");
    }
  }
  return 0;
}
