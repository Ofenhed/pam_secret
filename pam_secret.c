#include "creds.h"
#include "daemon.h"
#include "extern.h"
#include "hash.h"
#include "ipc.h"
#include "log.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
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

typedef struct {
  int auto_install;
  int translate_authtok;
  int silent;
} parsed_args;

static int parse_args(int argc, const char **argv, parsed_args *parsed) {
  static int first_parse = 1;
  const char **args_end = argv + argc;
  int result = 0;
  memset(parsed, 0, sizeof(*parsed));

  while (argv < args_end) {
    if (strcmp("auto_install", *argv) == 0) {
      parsed->auto_install = 1;
    } else if (strcmp("translate_authtok", *argv) == 0) {
      parsed->translate_authtok = 1;
    } else if (strcmp("silent", *argv) == 0) {
      parsed->silent = 1;
    } else {
      if (first_parse) {
        log_warning("Unknown argument \"%s\"", *argv);
      }
      result = -1;
    }
    argv += 1;
  }
  first_parse = 0;
  return result;
}

/* expected hook */
EXPORTED PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                       const char **argv) {
  return PAM_SUCCESS;
}

EXPORTED PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                         int argc, const char **argv) {
  return PAM_SUCCESS;
}

static FILE *flogger() {
  static FILE *flog = NULL;
  static int have_log = -1;
  int logger = get_default_log_output();
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

uid_t __pam_secret_saved_user_uid = INVALID_USER;
static int pam_save_user_uid(pam_handle_t *pamh) {
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
  __pam_secret_saved_user_uid = userPwd->pw_uid;
  struct group *group = getgrnam(manager_group_name());
  if (group == NULL) {
    errno = ENOENT;
    log_error("Could not find group %s", manager_group_name());
    return PAM_SYSTEM_ERR;
  }
  char **group_member = group->gr_mem;
  while (*group_member != NULL &&
         strcmp(*group_member, userPwd->pw_name) != 0) {
    log_debug("%s is member", *group_member);
    ++group_member;
  }
  if (*group_member == NULL) {
    log_debug("Not member of pam_secret group");
    return PAM_IGNORE;
  }

  return PAM_SUCCESS;
}

static uid_t pam_get_user_uid(void) { return __pam_secret_saved_user_uid; }

static int daemon_socket(int open) {
  static int sock = -1;
  if (sock == -1 && open) {
    flogger();
    if ((sock = connect_daemon(pam_get_user_uid)) == -1) {
      int child_pid;
      log_trace("Forking");
      if ((child_pid = fork()) == -1) {
        log_error("Could not fork daemon");
        return -1;
      } else if (child_pid == 0) {
        log_debug("Launching daemon");
        uid_t target_user = pam_get_user_uid();
        gid_t target_group = manager_group();
        PROP_CRIT(setresgid(target_group, target_group, target_group));
        PROP_CRIT(setresuid(target_user, target_user, target_user));
        char *args[] = {"/usr/sbin/pam_secret", "daemon", NULL};
        int logger = get_default_log_output();
        dup2(logger, stdout_fd);
        dup2(logger, stderr_fd);
        if (execv(args[0], args) == -1) {
          log_error("Could not execute daemon: %s", strerror(errno));
          exit(EXIT_FAILURE);
        }
      } else {
        int wstatus;
        log_trace("Waiting for daemon");
        waitpid(child_pid, &wstatus, 0);
        if (!WIFEXITED(wstatus)) {
          log_error("Child process scrypt crashed: %s", strerror(errno));
          return -1;
        } else if (WEXITSTATUS(wstatus) == ENOENT) {
          errno = ENOENT;
          return -1;
        } else if (WEXITSTATUS(wstatus) != 0) {
          log_error("Failed to start daemon");
          return -1;
        } else {
          if ((sock = connect_daemon(pam_get_user_uid)) == -1) {
            log_error("Could not connect to daemon: %s", strerror(errno));
            return -1;
          } else {
            log_debug("Connected to daemon");
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

  log_trace("Truncating shared memory location to %zu bytes", auth_token_len);
  PROP_CRIT(ftruncate(secret_fd, auth_token_len));
  if (auth_token_len > 0) {
    unsigned char *msg_mem;
    msg_mem =
        crit_mmap(NULL, auth_token_len, PROT_WRITE, MAP_SHARED, secret_fd, 0);
    DEFER({ munmap(msg_mem, auth_token_len); });

    log_trace("Copying password of length %zu\n", auth_token_len);
    memcpy(msg_mem, p_auth_token, auth_token_len);
  }
  return auth_token_len;
}

static int transform_auth_token(pam_handle_t *pamh, int pam_item_id,
                                int auth_token) {
  sha256_hash_t *new_user_cred_raw;
  if ((new_user_cred_raw = mmap(NULL, sizeof(*new_user_cred_raw), PROT_READ,
                                MAP_SHARED, auth_token, 0)) != MAP_FAILED) {
    DEFER({ munmap(new_user_cred_raw, sizeof(*new_user_cred_raw)); });
    sha256_hash_hex_t *new_user_cred;
    crit_memfd_secret_alloc(new_user_cred);
    DEFER({ munmap(new_user_cred, sizeof(*new_user_cred)); });
    *new_user_cred = hash_to_hex(new_user_cred_raw);
    log_debug("Setting authentication token %s", new_user_cred->printable);
    pam_set_item(pamh, pam_item_id, new_user_cred->printable);
    return PAM_SUCCESS;
  }
  return PAM_SYSTEM_ERR;
}

void silence_logger() { set_default_log_output(open("/dev/null", O_WRONLY)); }

static int do_authenticate(pam_handle_t *pamh, int auth_token, int flags,
                           parsed_args *args) {

  auto flog = flogger();
  if (get_persistent_secret_fd(pam_get_user_uid()) == -1) {
    log_warning("No installed user credential");
    return PAM_AUTH_ERR;
  }

  int sock = daemon_socket(true);
  if (sock == -1 && errno == ENOENT) {
    return PAM_IGNORE;
  }

  int auth_token_fd = memfd_secret(O_CLOEXEC);
  if (auth_token_fd == -1) {
    return PAM_BUF_ERR;
  }
  DEFER({ close(auth_token_fd); });
  int auth_token_len = read_auth_token(pamh, auth_token, auth_token_fd);
  if (auth_token_len == -1) {
    fprintf(flog, "Could not read auth token\n");
    return PAM_CRED_INSUFFICIENT;
  }
  if (auth_token_len == 0) {
    log_error("Not accepting empty password");
    return PAM_CRED_INSUFFICIENT;
  }

  msg_info_t msg;
  msg.kind = MSG_AUTHENTICATE;
  msg.data_len = auth_token_len;
  if (send_peer_msg(sock, msg, &auth_token_fd, 0) == -1) {
    perror("Could not send message to daemon");
    return PAM_SERVICE_ERR;
  }

  while (true) {
    int msg_fd;
    int len = recv_peer_msg(sock, &msg, &msg_fd);
    DEFER({
      if (msg_fd != -1)
        close(msg_fd);
    });
    if (len == -1 || len == 0) {
      perror("Could not receive message from daemon");
      return PAM_SERVICE_ERR;
    }
    log_debug("Got message %i", msg.kind);

    if (msg.kind == MSG_AUTHENTICATED) {
      log_debug("Authentication successful");
      if (args->translate_authtok) {
        transform_auth_token(pamh, auth_token, msg_fd);
      }
      return PAM_SUCCESS;
    } else if (msg.kind == MSG_NOT_AUTHENTICATED) {
      log_warning("Authentication failed");
      return PAM_AUTH_ERR;
    }
  }
}

EXPORTED PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                         int argc, const char **argv) {
  parsed_args args;
  parse_args(argc, argv, &args);
  if (flags & PAM_SILENT || args.silent)
    silence_logger();
  int tmp;
  if ((tmp = pam_save_user_uid(pamh)) != PAM_SUCCESS) {
    return tmp;
  }
  FILE *flog = flogger();
  static int authentication_result = PAM_AUTH_ERR;
  int has_persistent_secret =
      get_persistent_secret_fd(pam_get_user_uid()) != -1;
  int auto_install = args.auto_install &&
                     authentication_result == PAM_AUTH_ERR &&
                     !has_persistent_secret;
  if (flags & PAM_PRELIM_CHECK) {
    if (!has_persistent_secret)
      return authentication_result = PAM_SUCCESS;
    return authentication_result =
               do_authenticate(pamh, PAM_OLDAUTHTOK, flags, &args);
  } else if (flags & PAM_UPDATE_AUTHTOK &&
             (authentication_result == PAM_SUCCESS ||
              authentication_result == PAM_IGNORE)) {
    if (has_persistent_secret) {
      int sock = daemon_socket(true);
      if (sock == -1 && errno == ENOENT) {
        return PAM_IGNORE;
      }
      log_debug("Trying to install new auth token, auto install is %i",
                auto_install);
      int secret_fd = memfd_secret(O_CLOEXEC);
      if (secret_fd == -1) {
        log_error("Could not create memfd secret");
        daemon_socket(0);
        return PAM_BUF_ERR;
      }
      DEFER({ close(secret_fd); });
      int secret_len;
      if ((secret_len = read_auth_token(pamh, PAM_AUTHTOK, secret_fd)) == -1) {
        log_error("Could not read auth token");
        daemon_socket(0);
        return PAM_CRED_INSUFFICIENT;
      }
      if (secret_len == 0) {
        log_error("Not accepting empty password");
        return PAM_CRED_INSUFFICIENT;
      }
      msg_info_t msg;
      msg.data_len = secret_len;
      msg.kind = MSG_UPDATE_PASSWORD;
      if (send_peer_msg(sock, msg, &secret_fd, 0) == -1) {
        log_error("Could not send message to daemon");
        daemon_socket(0);
        return PAM_SERVICE_ERR;
      }
      while (true) {
        int msg_fd;
        int len = recv_peer_msg(sock, &msg, &msg_fd);
        DEFER({
          if (msg_fd != -1)
            close(msg_fd);
        });
        if (len == -1 || len == 0) {
          log_error("Could not receive message from daemon");
          daemon_socket(0);
          return PAM_SERVICE_ERR;
        }
        if (msg.kind == MSG_UPDATE_PASSWORD_SUCCESS) {
          log_debug("Password change success");
          transform_auth_token(pamh, PAM_AUTHTOK, msg_fd);
          daemon_socket(0);
          return PAM_SUCCESS;
        } else if (msg.kind == MSG_UNKNOWN_ERROR ||
                   msg.kind == MSG_NOT_AUTHENTICATED) {
          log_debug("Password change failed");
          daemon_socket(0);
          return PAM_SERVICE_ERR;
        } else {
          log_trace("Got unexpected message %i", msg.kind);
        }
      }
    } else {
      log_debug("Trying to install new auth");
      const char *p_auth_token;

      int retval = pam_get_authtok(pamh, PAM_AUTHTOK, &p_auth_token, NULL);
      if (retval != PAM_SUCCESS) {
        fprintf(flog, "Could not read auth token for user\n");
        return retval;
      }
      const size_t auth_token_len = strlen(p_auth_token);

      int new_token =
          open(get_runtime_dir(pam_get_user_uid), O_TMPFILE | O_RDWR, 0400);
      int cred_len;
      if ((cred_len = create_user_persistent_cred_secret(
               -1, (unsigned char *)p_auth_token, auth_token_len, new_token)) ==
          -1) {
        log_error("Could not create persistent secret: %s", strerror(errno));
        close(new_token);
        return PAM_SYSTEM_ERR;
      }
      uid_t target_user = pam_get_user_uid();
      if (target_user == INVALID_USER) {
        return PAM_SYSTEM_ERR;
      }
      if (install_user_session_cred_secret(new_token, target_user, true) ==
          -1) {
        log_error("Could not install persistent secret: %s", strerror(errno));
        return PAM_SYSTEM_ERR;
      }
      get_persistent_secret_filename(target_user);
      if (args.translate_authtok) {
        sha256_hash_t new_auth_token_raw;
        if (pam_translated_user_auth_token((unsigned char *)p_auth_token,
                                           auth_token_len,
                                           &new_auth_token_raw) == -1) {
          return PAM_SYSTEM_ERR;
        }
        sha256_hash_hex_t token = hash_to_hex(&new_auth_token_raw);
        log_debug("Setting authentication token to %s", token.printable);
        pam_set_item(pamh, PAM_AUTHTOK, token.printable);
      }
    }
  }
  return PAM_IGNORE;
}

/* expected hook, this is where custom stuff happens */
EXPORTED PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                            int argc, const char **argv) {
  parsed_args args;
  parse_args(argc, argv, &args);
  if (flags & PAM_SILENT || args.silent)
    silence_logger();
  int tmp;
  DEFER({ daemon_socket(0); });
  if ((tmp = pam_save_user_uid(pamh)) != PAM_SUCCESS) {
    return tmp;
  }
  return do_authenticate(pamh, PAM_AUTHTOK, flags, &args);
}
