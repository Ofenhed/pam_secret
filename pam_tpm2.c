#include "daemon.h"
#include "extern.h"
#include "ipc.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* expected hook */
EXPORTED PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                       const char **argv) {
  return PAM_SUCCESS;
}

EXPORTED PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                         int argc, const char **argv) {
  return PAM_SUCCESS;
}

// static int tpm_function(const char *sudoUser, const char *exec,
//                         const char *argument) {
//   if (sudoUser == NULL) {
//     sudoUser = "tss";
//   }
//   const char *tpmArgs[] = {AS_USER(sudoUser),
//                            exec,     argument, NULL};
//   return exec_blocking(AS_USER_BIN, tpmArgs);
// }

static int logger = 2;
static FILE *flogger() {
  static FILE *flog = NULL;
  static int have_log = -1;
  if (have_log != logger) {
    if (flog != NULL) {
      fclose(flog);
    }
    if ((flog = fdopen(logger, "w"))) {
      have_log = logger;
    }
  }
  return flog;
}

static int daemon_socket(int open) {
  static int sock = -1;
  if (sock == -1 && open) {
    auto flog = flogger();
    uid_t target_user = getuid();
    if ((sock = connect_daemon()) == -1) {
      int child_pid;
      fprintf(flog, "Forking");
      if ((child_pid = fork()) == -1) {
        fprintf(flog, "Could not fork daemon\n");
        return PAM_SERVICE_ERR;
      } else if (child_pid == 0) {
        fprintf(flog, "Launching daemon\n");
        setresuid(target_user, target_user, target_user);
        char *args[] = {"/usr/sbin/pam_secret", "daemon", NULL};
        dup2(logger, 1);
        dup2(logger, 2);
        if (execv(args[0], args) == -1) {
          fprintf(flog, "Could not execute daemon: %s\n", strerror(errno));
          return -1;
        }
      } else {
        int wstatus;
        fprintf(flog, "Waiting for daemon\n");
        waitpid(child_pid, &wstatus, 0);
        if (!WIFEXITED(wstatus)) {
          fprintf(flog, "Child process scrypt crashed: %s\n", strerror(errno));
          return -1;
        } else if (WEXITSTATUS(wstatus) != 0) {
          fprintf(flog, "Failed to start daemon\n");
          return PAM_SERVICE_ERR;
        } else {
          if ((sock = connect_daemon()) == -1) {
            fprintf(flog, "Could not connect to daemon: %s\n", strerror(errno));
            return PAM_SERVICE_ERR;
          } else {
            fprintf(flog, "Connected to daemon\n");
          }
        }
      }
    }
  } else if (sock != -1 && !open) {
    int retval = close(sock);
    sock = -1;
    return retval;
  }
  return sock;
}

static int read_auth_token(pam_handle_t *pamh, int auth_token, int secret_fd) {
  int retval;
  const char *p_auth_token;
  auto flog = flogger();
  retval = pam_get_authtok(pamh, auth_token, &p_auth_token, NULL);
  if (retval != PAM_SUCCESS) {
    fprintf(flog, "Could not read auth token for user\n");
    return -1;
  }
  const size_t auth_token_len = strlen(p_auth_token);

  fprintf(flog, "Truncating shared memory location to %zu bytes\n",
          auth_token_len);
  if (ftruncate(secret_fd, auth_token_len) == -1) {
    fprintf(flog, "Could not truncate memory\n");
    return -1;
  }
  unsigned char *msg_mem;
  if ((msg_mem = mmap(NULL, auth_token_len, PROT_WRITE, MAP_SHARED, secret_fd,
                      0)) == MAP_FAILED) {
    fprintf(flog, "Could not map memory\n");
    return -1;
  }

  fprintf(flog, "Copying password of length %zu\n", auth_token_len);
  memcpy(msg_mem, p_auth_token, auth_token_len);
  munmap(msg_mem, auth_token_len);
  return auth_token_len;
}

static int do_authenticate(pam_handle_t *pamh, int auth_token, int flags,
                           int argc, const char **argv) {
  if (flags & PAM_SILENT) {
    logger = open("/dev/null", O_WRONLY);
    if (logger == -1) {
      return PAM_SYSTEM_ERR;
    }
  }
  auto flog = flogger();

  const char *pUsername;
  int retval = pam_get_user(pamh, &pUsername, NULL);
  if (retval != PAM_SUCCESS) {
    fprintf(flog, "Could not get user\n");
    return retval;
  }
  struct passwd *userPwd = getpwnam(pUsername);
  if (userPwd == NULL) {
    fprintf(flog, "Could not read user info\n");
    return PAM_SYSTEM_ERR;
  }

  int sock = daemon_socket(1);

  int auth_token_fd = memfd_secret(O_CLOEXEC);
  if (auth_token_fd == -1) {
    return PAM_BUF_ERR;
  }
  int auth_token_len = read_auth_token(pamh, auth_token, auth_token_fd);
  if (auth_token_len == -1) {
    fprintf(flog, "Could not read auth token\n");
    return PAM_SYSTEM_ERR;
  }

  msg_info_t msg;
  msg_context_t context[2] = {{auth_token_fd}};
  msg.kind = MSG_AUTHENTICATE;
  msg.data_len = auth_token_len;
  if (send_peer_msg(sock, msg, context, 1, 0) == -1) {
    return PAM_SERVICE_ERR;
  }

  while (true) {
    int len = recv_peer_msg(sock, &msg, context);
    if (len == -1 || len == 0) {
      return PAM_SERVICE_ERR;
    }
    fprintf(flog, "Got message %i\n", msg.kind);

    if (msg.kind == MSG_AUTHENTICATED) {
      fprintf(flog, "You're good\n");
      return PAM_SUCCESS;
    } else if (msg.kind == MSG_NOT_AUTHENTICATED) {
      return PAM_AUTH_ERR;
    }
  }
}

EXPORTED PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                         int argc, const char **argv) {
  int sock = daemon_socket(1);
  FILE *flog = flogger();
  if (flags & PAM_PRELIM_CHECK) {
    return do_authenticate(pamh, PAM_OLDAUTHTOK, flags, argc, argv);
  } else if (flags & PAM_UPDATE_AUTHTOK) {
    int secret_fd = memfd_secret(O_CLOEXEC);
    if (secret_fd == -1) {
      daemon_socket(0);
      return PAM_BUF_ERR;
    }
    int secret_len;
    if ((secret_len = read_auth_token(pamh, PAM_AUTHTOK, secret_fd)) == -1) {
      daemon_socket(0);
      return PAM_SYSTEM_ERR;
    }
    msg_info_t msg;
    msg_context_t context[2] = {{secret_fd}};
    msg.data_len = secret_len;
    msg.kind = MSG_UPDATE_PASSWORD;
    if (send_peer_msg(sock, msg, context, 1, 0) == -1) {
      daemon_socket(0);
      return PAM_SERVICE_ERR;
    }
    while (true) {
      int len = recv_peer_msg(sock, &msg, context);
      if (len == -1 || len == 0) {
        daemon_socket(0);
        return PAM_SERVICE_ERR;
      }
      fprintf(flog, "Got message %i\n", msg.kind);
      if (msg.kind == MSG_UPDATE_PASSWORD_SUCCESS) {
        daemon_socket(0);
        return PAM_SUCCESS;
      } else if (msg.kind == MSG_UNKNOWN_ERROR ||
                 msg.kind == MSG_NOT_AUTHENTICATED) {
        daemon_socket(0);
        return PAM_SERVICE_ERR;
      }
    }
  }
  return PAM_IGNORE;
}

/* expected hook, this is where custom stuff happens */
EXPORTED PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                            int argc, const char **argv) {
  int ret = do_authenticate(pamh, PAM_AUTHTOK, flags, argc, argv);
  daemon_socket(0);
  return ret;
}
