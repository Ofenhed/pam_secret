#include "creds.h"
#include "extern.h"
#include "hash.h"
#include "log.h"
#include "path.h"
#include "session_mask.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PASSWD_DIR
#define PASSWD_DIR "/etc/shadow.enc"
#endif

#ifndef PERSISTENT_CREDENTIAL_FORMAT
#define PERSISTENT_CREDENTIAL_FORMAT "protected-user-cred-%i"
#endif
#ifndef PERSISTENT_CREDENTIAL_REQUEST_PREFIX
#define PERSISTENT_CREDENTIAL_REQUEST_PREFIX ".tmp-new-"
#endif
#ifndef SESSION_WRAPPED_DIR
#define SESSION_WRAPPED_DIR "/var/run/user/%u/sessioncreds.sensitive"
#endif
#ifndef SESSION_SECRET_DIR
#define SESSION_SECRET_DIR "/var/run/user/%u/sessioncreds.secret"
#endif

int session_encrypted_fd = -1, session_encrypted_data_len = 0,
    session_secret_fd = -1;

#ifdef SYSTEM_SECRET_FILENAME_OVERRIDE
#define SYSTEM_SECRET_FILENAME                                                 \
  STRINGIZE_VALUE_OF(SYSTEM_SECRET_FILENAME_OVERRIDE)
#else
#define SYSTEM_SECRET_FILENAME "enc-auth"
#endif

#ifdef SERVICE_GROUP
#define SERVICE_GROUP_STR STRINGIZE_VALUE_OF(SERVICE_GROUP)
#else
#define SERVICE_GROUP_STR "enc-auth"
#endif

gid_t manager_group() {
  static gid_t manager_group = INVALID_GROUP;
  if (manager_group == INVALID_GROUP) {
    struct group *gr = getgrnam(SERVICE_GROUP_STR);
    if (gr == NULL) {
      errno = ENOENT;
      perror("Could not find group " SERVICE_GROUP_STR);
      return -1;
    }
    manager_group = gr->gr_gid;
  }
  return manager_group;
}

const char *manager_group_name() { return SERVICE_GROUP_STR; }

scrypt_action_t set_scrypt_input_data(scrypt_action_t params,
                                      const unsigned char *secret,
                                      int secret_len) {
  params.input_is_fd = 0;
  params.input.data.ptr = secret;
  params.input.data.len = secret_len;
  return params;
}
scrypt_action_t set_scrypt_input_fd(scrypt_action_t params, int fd) {
  params.input_is_fd = 1;
  params.input.fd = fd;
  return params;
}

int set_memfd_random(int fd, int len) {
  if (len <= 0) {
    errno = EINVAL;
    return -1;
  }
  char *target = mmap(NULL, len, PROT_WRITE, MAP_SHARED, fd, 0);
  if (target == MAP_FAILED) {
    perror("Could not map memory");
    return -1;
  }
  DEFER({ munmap(target, len); });
  int result;
  PROP_ERR(result = write_random_data(target, len));
  return result;
}

int xor_secret_data(const secret_state_t *data, secret_state_t *output) {
  const secret_state_t *key = get_session_mask();
  unsigned char *out_ptr = *output;
  const unsigned char *data_ptr = *data, *key_ptr = *key;
  for (size_t i = 0; i < sizeof(secret_state_t); ++i) {
    out_ptr[i] = data_ptr[i] ^ key_ptr[i];
  }
  return 0;
}

int xor_secret_data_fd(int source_fd, int destination_fd) {
  secret_state_t *source, *dest;
  source =
      mmap(NULL, sizeof(secret_state_t), PROT_READ, MAP_SHARED, source_fd, 0);
  if (source == MAP_FAILED)
    return -1;
  DEFER({ munmap(source, sizeof(*source)); });
  PROP_ERR(ftruncate(destination_fd, sizeof(secret_state_t)));
  dest = mmap(NULL, sizeof(secret_state_t), PROT_WRITE, MAP_SHARED,
              destination_fd, 0);
  if (dest == MAP_FAILED) {
    return -1;
  }
  DEFER({ munmap(dest, sizeof(*dest)); });
  PROP_ERR(xor_secret_data(source, dest));
  return 0;
}

int invalidate_session_secret() {
  if (session_secret_fd != -1) {
    PROP_ERR(close(session_secret_fd));
    session_secret_fd = -1;
  }
  return 0;
}

int get_persistent_secret_filename_into(uid_t user, char *path, int max_len) {
  int written = snprintf(path, max_len, PERSISTENT_CREDENTIAL_FORMAT, user);
  if (written >= max_len) {
    return -1;
  } else {
    return written + 1;
  }
}

const char *get_persistent_storage_location() { return PASSWD_DIR; }

const char *get_system_secret_filename() { return SYSTEM_SECRET_FILENAME; }

int get_persistent_storage_fd() {
  static int storage = -1;
  if (storage == -1) {
    PROP_ERR(storage = open(PASSWD_DIR, O_DIRECTORY, 0));
  }
  return storage;
}

int get_persistent_secret_path_fd(uid_t user) {
  static int secret_path_fd = -1;
  static uid_t fd_user = INT_MAX;
  if (secret_path_fd == -1 || fd_user != user) {
    if (secret_path_fd != -1)
      close(secret_path_fd);
    secret_path_fd = -1;
    int storage;
    PROP_ERR(storage = get_persistent_storage_fd());
    fd_user = user;
    secret_path_fd = openat(storage, get_persistent_secret_filename(user),
                            O_PATH | O_CLOEXEC, 0);
  }
  return secret_path_fd;
}

int open_persistent_secret_fd(uid_t user) {
  int secret_path_fd = get_persistent_secret_path_fd(user);
  int fd = openat(get_proc_self_fds_fd(), tmp_sprintf("%i", secret_path_fd),
                  O_RDONLY | O_CLOEXEC, 0);
  return fd;
}

int get_persistent_secret_fd(uid_t user) {
  static int secret_fd = -1;
  static uid_t fd_user = UINT_MAX;
  if (secret_fd == -1 || fd_user != user) {
    if (secret_fd != -1) {
      close(secret_fd);
    }
    secret_fd = open_persistent_secret_fd(user);
  }
  return secret_fd;
}

const char *get_persistent_secret_filename(uid_t user) {
  static char path[256];
  if (get_persistent_secret_filename_into(user, path, ARR_LEN(path)) == -1) {
    return NULL;
  } else {
    return path;
  }
}

scrypt_action_t default_trivial_args() {
  scrypt_params_local_t def = {0.1, 1 << 20, 0.1};
  scrypt_action_t action;
  action.op = ENCRYPT;
  action.enc_params.params.local = def;
  action.enc_params.is_local = true;
  return action;
}

scrypt_action_t default_persistent_args() {
  scrypt_params_local_t def = {10, 1 << 30, 0.5};
  scrypt_action_t action;
  action.op = ENCRYPT;
  action.enc_params.params.local = def;
  action.enc_params.is_local = true;
  return action;
}

scrypt_action_t default_session_args() {
  scrypt_params_local_t def = {2, 1 << 22, 0.5};
  scrypt_action_t action;
  action.op = ENCRYPT;
  action.enc_params.params.local = def;
  action.enc_params.is_local = true;
  return action;
}

// This will leak file descriptors on failure
// out_secret_fd should be an memfd_secret
// Returns size of read data
int scrypt_into_fd(scrypt_action_t params, const unsigned char *user_password,
                   int user_password_len, int out_secret_fd) {
  const int rx = PIPE_RX;
  const int tx = PIPE_TX;
  int password_pipe[2] = {0}, secret_pipe[2] = {0}, result_pipe[2] = {0};
  int child_pid;
  PROP_ERR(pipe2(password_pipe, O_CLOEXEC));
  PROP_ERR(pipe2(result_pipe, O_CLOEXEC));
  if (!params.input_is_fd) {
    PROP_ERR(pipe2(secret_pipe, O_CLOEXEC));
  }
  PROP_ERR(child_pid = fork());
  if (child_pid == 0) {
    char args_buf[256];
    char *args_ptr = args_buf;
    const char *const args_buf_end = ARR_END(args_buf);
    const char *scrypt_args[20] = {};
    const char **end_args = ARR_END(scrypt_args);
    const char **curr_arg = scrypt_args;

    log_debug("%scrypting data\n", params.op == ENCRYPT ? "En" : "De");
    PROP_ERR(add_arg(&curr_arg, end_args, "/usr/bin/scrypt"));
    PROP_ERR(to_scrypt_args(&params, &curr_arg, end_args));
    PROP_ERR(add_arg(&curr_arg, end_args, "--passphrase"));
    PROP_ERR(add_arg(&curr_arg, end_args, "dev:stdin-once"));

    PROP_ERR(inherit_fd_as(password_pipe[rx], 0));
    int secret_fd, result_fd;
    if (params.input_is_fd) {
      PROP_ERR(secret_fd = inherit_fd(params.input.fd));
    } else {
      PROP_ERR(secret_fd = inherit_fd(secret_pipe[rx]));
    }
    PROP_ERR(add_arg(
        &curr_arg, end_args,
        bufnprintf(&args_ptr, args_buf_end, "/proc/self/fd/%i", secret_fd)));
    PROP_ERR(result_fd = inherit_fd(result_pipe[tx]));
    PROP_ERR(add_arg(
        &curr_arg, end_args,
        bufnprintf(&args_ptr, args_buf_end, "/proc/self/fd/%i", result_fd)));
    if (execv(scrypt_args[0], (char *const *)scrypt_args) == -1) {
      perror("Child process execve failed");
      return -1;
    }
    return 0;
  } else {
    DEBUG_PROP_ERR(close(password_pipe[rx]));
    int password_pipe_tx = password_pipe[tx];
    DEFER({ close(password_pipe_tx); });
    if (params.input_is_fd) {
      secret_pipe[tx] = -1;
    } else {
      DEBUG_PROP_ERR(close(secret_pipe[rx]));
    }
    int secret_pipe_tx = secret_pipe[tx];
    DEFER({
      if (!params.input_is_fd)
        close(secret_pipe_tx);
    });
    DEBUG_PROP_ERR(close(result_pipe[tx]));
    int result_pipe_rx = result_pipe[rx];
    DEFER({
      if (result_pipe_rx != -1)
        close(result_pipe_rx);
    });
    int epollfd;
    PROP_ERR(epollfd = epoll_create1(O_CLOEXEC));
    DEFER({ close(epollfd); });
    int saved_len = 0;
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    if (!params.input_is_fd) {
      ev.data.fd = secret_pipe_tx;
      PROP_ERR(epoll_ctl(epollfd, EPOLL_CTL_ADD, secret_pipe_tx, &ev));
    }
    ev.data.fd = password_pipe_tx;
    PROP_ERR(epoll_ctl(epollfd, EPOLL_CTL_ADD, password_pipe_tx, &ev));
    ev.events = EPOLLIN;
    ev.data.fd = result_pipe_rx;
    PROP_ERR(epoll_ctl(epollfd, EPOLL_CTL_ADD, result_pipe_rx, &ev));
    const long page_size = sysconf(_SC_PAGE_SIZE);
    while (true) {
      struct epoll_event events[5];
      int nfds, c;
      PROP_ERR(nfds = epoll_wait(epollfd, events, ARR_LEN(events), -1));
      for (int n = 0; n < nfds; ++n) {
        int is_secret_pipe =
            !params.input_is_fd && events[n].data.fd == secret_pipe_tx;
        if (is_secret_pipe || events[n].data.fd == password_pipe_tx) {
          const unsigned char **source;
          int *source_len;
          if (is_secret_pipe) {
            source = &params.input.data.ptr;
            source_len = &params.input.data.len;
          } else {
            source = &user_password;
            source_len = &user_password_len;
          }
          PROP_ERR(c = write(events[n].data.fd, *source, *source_len));
          if (c == 0) {
            log_debug("Could not write complete buffer");
            return -1;
          }
          (*source) += c;
          (*source_len) -= c;
          if (*source_len == 0) {
            PROP_ERR(epoll_ctl(epollfd, EPOLL_CTL_DEL, events[n].data.fd,
                               &events[n]));
            close(events[n].data.fd);
            if (is_secret_pipe) {
              secret_pipe_tx = -1;
            } else {
              password_pipe_tx = -1;
            }
          }
        } else if (events[n].data.fd == result_pipe_rx) {
          int saved_page_offset = saved_len & (page_size - 1);
          if (saved_page_offset == 0) {
            PROP_ERR(ftruncate(out_secret_fd,
                               saved_len - saved_page_offset + page_size));
          }
          char *output =
              mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                   out_secret_fd, saved_len - saved_page_offset);
          if (output == MAP_FAILED) {
            perror("Could not map output");
            PROP_ERR(-1)
            return -1;
          }
          DEFER({ munmap(output, page_size); });
          PROP_ERR(c = read(result_pipe_rx, output + saved_page_offset,
                            page_size - saved_page_offset));
          saved_len += c;
          if (c == 0) {
            int wstatus;
            waitpid(child_pid, &wstatus, 0);
            if (!WIFEXITED(wstatus)) {
              perror("Child process scrypt crashed");
              return -1;
            } else if (WEXITSTATUS(wstatus) != 0) {
              errno = EACCES;
              return -1;
            } else {
              int __attribute__((unused)) _may_fail =
                  ftruncate(out_secret_fd, saved_len);
              return saved_len;
            }
          }
        }
      }
    }
  }
  return -1;
}

int install_user_session_cred_secret(int source_fd, uid_t user,
                                     int allow_create) {
  int output_fd, wd;
  PROP_ERR(wd = get_persistent_storage_fd());
  PROP_ERR(output_fd = openat(wd, ".", O_TMPFILE | O_WRONLY, 0400));
  DEFER({ close(output_fd); });
  int r, w;
  char buf[4096];
  while ((r = read(source_fd, buf, ARR_LEN(buf))) > 0) {
    char *out_ptr = buf;
    const char *const out_end = buf + r;
    while (out_ptr < out_end) {
      PROP_ERR(w = write(output_fd, out_ptr, out_end - out_ptr));
      out_ptr += w;
      if (w == 0) {
        errno = ENOSPC;
        return -1;
      }
    }
  }
  PROP_ERR(r);
  char printf_buf[256];
  char *printf_ptr = printf_buf;
  const char *const printf_end = ARR_END(printf_buf);
  int target_file_offset;

  const char *tmpfile = bufnprintf(
      &printf_ptr, printf_end, "%s%n%s", PERSISTENT_CREDENTIAL_REQUEST_PREFIX,
      &target_file_offset, get_persistent_secret_filename(user));
  const char *newfile = tmpfile + target_file_offset;
  const char *memfile_path =
      bufnprintf(&printf_ptr, printf_end, "/proc/self/fd/%i", output_fd);
  assert(tmpfile != NULL && memfile_path != NULL);
  PROP_ERR(linkat(AT_FDCWD, memfile_path, wd, tmpfile, AT_SYMLINK_FOLLOW));
  // TODO: The problem is that the detection of an existing file fails, so it
  // tries to create a new file instead of replacing the existing file. Not sure
  // why it fails, though.
  DEFER({ unlinkat(wd, tmpfile, 0); });
  gid_t group = manager_group();
  if (fchown(output_fd, user, group) == -1) {
    log_warning("Could not set group for user secret file");
  }
  if (!allow_create) {
    if (faccessat(wd, newfile, F_OK, 0) == 0) {
      perror("Unable to create new credential");
      return -1;
    }
  }
  log_trace("Overwriting old credential file");
  PROP_ERR(renameat(wd, tmpfile, wd, newfile));
  log_trace("Attempting to change owner to %i:%i\n", user, group);
  if (fchownat(wd, newfile, user, group, 0) == -1) {
    log_warning("Coult not set mode for user secret file");
  }
  return 0;
}

int hashed_user_cred(const unsigned char *user_password, int user_password_len,
                     sha256_hash_t *output) {
  int fd;
  PROP_ERR(fd = get_system_secret_fd());
  secret_state_t *system_secret =
      crit_mmap(NULL, sizeof(*system_secret), PROT_READ, MAP_SHARED, fd, 0);
  DEFER({ munmap(system_secret, sizeof(*system_secret)); });
  hash_state_t *hash_state;
  crit_memfd_secret_alloc(hash_state);
  DEFER({ munmap(hash_state, sizeof(*hash_state)); });
  hmac(hash_state, HASH_TYPE_STORAGE_ENCRYPTION_KEY,
       STR_LEN(HASH_TYPE_STORAGE_ENCRYPTION_KEY), user_password,
       user_password_len);
  hmac_msg(hash_state, *system_secret, sizeof(*system_secret));
  hmac_finalize(hash_state, output);
  return 0;
}

int pam_translated_user_auth_token(const unsigned char *user_password,
                                   int user_password_len,
                                   sha256_hash_t *output) {
  secret_state_t *session;
  if (!(session = map_session_cred()))
    return -1;

  hash_state_t *auth_token_generator;
  crit_memfd_secret_alloc(auth_token_generator);
  DEFER({ munmap(auth_token_generator, sizeof(*auth_token_generator)); });
  hmac(auth_token_generator, HASH_TYPE_USER_PASSWORD,
       STR_LEN(HASH_TYPE_USER_PASSWORD), user_password, user_password_len);
  hmac_msg(auth_token_generator, *session, sizeof(*session));
  crit_munmap(session);
  secret_state_t *system_secret =
      crit_mmap(NULL, sizeof(*system_secret), PROT_READ, MAP_SHARED,
                get_system_secret_fd(), 0);
  DEFER({ munmap(system_secret, sizeof(*system_secret)); });
  hmac_msg(auth_token_generator, *system_secret, sizeof(*system_secret));
  hmac_finalize(auth_token_generator, output);
  return 0;
}

int create_user_persistent_cred_secret(int secret_fd,
                                       const unsigned char *user_password,
                                       int user_password_len,
                                       int persistent_fd) {
  const bool new_secret = (secret_fd == -1);
  if (new_secret) {
    PROP_ERR(secret_fd = memfd_secret(O_CLOEXEC));
    PROP_ERR(ftruncate(secret_fd, sizeof(secret_state_t)));
    PROP_ERR(set_memfd_random(secret_fd, sizeof(secret_state_t)));
  }
  DEFER({
    if (new_secret && session_secret_fd != secret_fd)
      close(secret_fd);
  });
  secret_state_t *secret_ptr =
      crit_mmap(0, sizeof(secret_state_t), PROT_READ, MAP_SHARED, secret_fd, 0);
  DEFER({ munmap(secret_ptr, sizeof(*secret_ptr)); });
  scrypt_action_t action = set_scrypt_input_data(
      default_persistent_args(), *secret_ptr, sizeof(secret_state_t));
  int persistent_len;
  sha256_hash_t *user_password_hash;
  crit_memfd_secret_alloc(user_password_hash);
  DEFER({ munmap(user_password_hash, sizeof(*user_password_hash)); });
  PROP_ERR(
      hashed_user_cred(user_password, user_password_len, user_password_hash));
  persistent_len = scrypt_into_fd(action, (unsigned char *)user_password_hash,
                                  sizeof(*user_password_hash), persistent_fd);
  if (persistent_len == -1) {
    return -1;
  }
  if (session_secret_fd != -1) {
    close(session_secret_fd);
    if (new_secret) {
      log_error("Generated new secret despite already having a secret");
    }
  } else {
    session_secret_fd = dup(secret_fd);
  }
  return persistent_len;
}

int get_system_secret_fd() {
  static int fd = -1;
  if (fd == -1) {
    int wd = get_persistent_storage_fd();
    PROP_ERR(
        fd = openat(wd, get_system_secret_filename(), O_RDONLY | O_CLOEXEC, 0));
  }
  return fd;
}

int get_session_secret_fd() {
  if (session_secret_fd == -1) {
    errno = EACCES;
    return -1;
  }
  return session_secret_fd;
}

secret_state_t *map_session_cred() {
  int fd = get_session_secret_fd();
  if (fd == -1) {
    return NULL;
  }
  return crit_mmap(NULL, sizeof(secret_state_t), PROT_READ, MAP_SHARED, fd, 0);
}

int unlock_persistent_user_secret(const unsigned char *user_password,
                                  int user_password_len) {
  uid_t user = geteuid();
  int storage_fd, persistent_fd, secret_fd, masked_fd, protected_fd;
  PROP_ERR(storage_fd = get_persistent_storage_fd());
  PROP_ERR(persistent_fd = get_persistent_secret_fd(user));
  lseek(persistent_fd, SEEK_SET, 0);

  scrypt_action_t action = {0};
  action.op = DECRYPT;
  action = set_scrypt_input_fd(action, persistent_fd);
  sha256_hash_t *user_password_hash;
  crit_memfd_secret_alloc(user_password_hash);
  PROP_ERR(
      hashed_user_cred(user_password, user_password_len, user_password_hash));
  PROP_CRIT(secret_fd = memfd_secret(O_CLOEXEC));
  DEFER({
    if (secret_fd != session_secret_fd) {
      close(secret_fd);
    }
  });
  int secret_len = scrypt_into_fd(action, (unsigned char *)user_password_hash,
                                  sizeof(*user_password_hash), secret_fd);
  if (secret_len != sizeof(secret_state_t)) {
    fprintf(stderr, "Invalid secret length %i\n", secret_len);
    return -1;
  }
  if (session_secret_fd != -1) {
    close(session_secret_fd);
  }
  session_secret_fd = secret_fd;
  assert(secret_len == SECRET_LEN);
  PROP_ERR(masked_fd = memfd_secret(O_CLOEXEC));
  PROP_ERR(xor_secret_data_fd(secret_fd, masked_fd));
  secret_state_t *mapped =
      mmap(NULL, sizeof(*mapped), PROT_READ, MAP_SHARED, masked_fd, 0);
  close(masked_fd);
  if (mapped == MAP_FAILED) {
    perror("Could not map masked");
    return -1;
  }
  DEFER({ munmap(mapped, sizeof(*mapped)); });
  action = set_scrypt_input_data(default_session_args(), *mapped,
                                 sizeof(secret_state_t));
  PROP_ERR(protected_fd = memfd_secret(O_CLOEXEC));
  DEFER({
    if (protected_fd != session_encrypted_fd)
      close(protected_fd);
  });
  int protected_len =
      scrypt_into_fd(action, (unsigned char *)user_password_hash,
                     sizeof(*user_password_hash), protected_fd);
  crit_munmap(mapped);
  if (protected_len == -1) {
    perror("Could not read into protected");
    return -1;
  }
  if (session_encrypted_fd != -1) {
    close(session_encrypted_fd);
  }
  session_encrypted_data_len = protected_len;
  session_encrypted_fd = protected_fd;
  return 0;
}

int unlock_plain_user_secret(const unsigned char *user_password,
                             int user_password_len) {
  if (session_encrypted_fd == -1 || session_encrypted_data_len == 0) {
    errno = ENODATA;
    return -1;
  }
  int secret_fd, protected_fd;
  if (session_encrypted_data_len <= 0) {
    errno = EINVAL;
    return -1;
  }
  unsigned char *encrypted_data =
      mmap(NULL, session_encrypted_data_len, PROT_READ, MAP_SHARED,
           session_encrypted_fd, 0);
  if (encrypted_data == MAP_FAILED) {
    perror("Could not map encrypted data");
    return -1;
  }
  DEFER({ munmap(encrypted_data, session_encrypted_data_len); });
  scrypt_action_t action = {0};
  action =
      set_scrypt_input_data(action, encrypted_data, session_encrypted_data_len);
  action.op = DECRYPT;
  sha256_hash_t *user_password_hash;
  crit_memfd_secret_alloc(user_password_hash);
  PROP_ERR(
      hashed_user_cred(user_password, user_password_len, user_password_hash));
  PROP_ERR(protected_fd = memfd_secret(O_CLOEXEC));
  DEFER({ close(protected_fd); });
  int decrypt = scrypt_into_fd(action, (unsigned char *)user_password_hash,
                               sizeof(*user_password_hash), protected_fd);
  if (decrypt != sizeof(secret_state_t)) {
    perror("Could not decrypt");
    return -1;
  }
  PROP_ERR(secret_fd = memfd_secret(O_CLOEXEC));
  PROP_ERR(xor_secret_data_fd(protected_fd, secret_fd));
  if (session_secret_fd != -1) {
    close(session_secret_fd);
  }
  session_secret_fd = secret_fd;
  return 0;
}

int lock_plain_user_secret() {
  if (session_secret_fd != -1) {
    int fd = session_secret_fd;
    session_secret_fd = -1;
    set_memfd_random(fd, sizeof(secret_state_t));
    return close(fd);
  }
  return 0;
}

int authenticate_user(const unsigned char *password, int password_len) {
  int cached_result, persistent_result;
  if ((cached_result = unlock_plain_user_secret(password, password_len)) ==
      -1) {
    if (errno == ENODATA) {
      if ((persistent_result =
               unlock_persistent_user_secret(password, password_len)) == -1) {
        if (errno == EACCES) {
          return 0;
        }
        perror("Could not log in");
        return -1;
      } else {
        return 1;
      }
    } else {
      perror("Something else failed");
      return 0;
    }
  }
  return 1;
}

// Args are valid until the next call to `to_scrypt_args`.
int to_scrypt_args(scrypt_action_t *action, const char ***args,
                   const char **args_end) {
  static char args_buf[1024];
  const char *const buf_end = ARR_END(args_buf);
  char *args_ptr = args_buf;
  if (action->op == DECRYPT) {
    PROP_ERR(add_arg(args, args_end, "dec"));
    return 0;
  } else if (action->op == ENCRYPT) {
    scrypt_params_t *params = &action->enc_params;
    PROP_ERR(add_arg(args, args_end, "enc"));
    if (params->is_local) {
      scrypt_params_local_t local = params->params.local;
      PROP_ERR(add_arg(args, args_end, "-M"));
      PROP_ERR(add_arg(args, args_end,
                       bufnprintf(&args_ptr, buf_end, "%lu", local.maxmem)));
      PROP_ERR(add_arg(args, args_end, "-m"));
      PROP_ERR(add_arg(args, args_end,
                       bufnprintf(&args_ptr, buf_end, "%f", local.maxmemfrac)));
      PROP_ERR(add_arg(args, args_end, "-t"));
      PROP_ERR(add_arg(args, args_end,
                       bufnprintf(&args_ptr, buf_end, "%f", local.maxtime)));
    } else {
      scrypt_params_work_t work = params->params.work;
      PROP_ERR(add_arg(args, args_end, "--logN"));
      PROP_ERR(add_arg(args, args_end,
                       bufnprintf(&args_ptr, buf_end, "%i", work.n)));
      PROP_ERR(add_arg(args, args_end, "-r"));
      PROP_ERR(add_arg(args, args_end,
                       bufnprintf(&args_ptr, buf_end, "%li", work.r)));
      PROP_ERR(add_arg(args, args_end, "-p"));
      PROP_ERR(add_arg(args, args_end,
                       bufnprintf(&args_ptr, buf_end, "%f", work.p)));
    }
    return 0;
  }
  errno = EINVAL;
  return -1;
}
