#include "creds.h"
#include "extern.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
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
#ifndef SESSION_WRAPPED_DIR
#define SESSION_WRAPPED_DIR "/var/run/user/%u/sessioncreds.sensitive"
#endif
#ifndef SESSION_SECRET_DIR
#define SESSION_SECRET_DIR "/var/run/user/%u/sessioncreds.secret"
#endif

int session_encrypted_fd = -1, session_encrypted_data_len = 0,
    session_secret_fd = -1;

#ifdef SYSTEM_SECRET_FILENAME_OVERRIDE
#define SYSTEM_SECRET_FILENAME STRINGIZE_VALUE_OF(SYSTEM_SECRET_FILENAME_OVERRIDE)
#else
#define SYSTEM_SECRET_FILENAME "enc-auth"
#endif

#ifdef SERVICE_GROUP
#define SERVICE_GROUP_STR STRINGIZE_VALUE_OF(SERVICE_GROUP)
#else
#define SERVICE_GROUP_STR "enc-auth"
#endif

gid_t manager_group() {
  static gid_t manager_group = -1;
  if (manager_group == -1) {
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

int memfd_secret2(int len, int flags) {
  int fd;
  PROP_ERR(fd = memfd_secret(flags));
  PROP_ERR(ftruncate(fd, len));
  return fd;
}

char *mmap_secret(int fd, int len, int prot) {
  if (len == -1) {
    perror("Could not get mmap size");
    return NULL;
  }
  return mmap(NULL, len, prot, MAP_ANONYMOUS, fd, 0);
}

int set_memfd_random(int fd, int len) {
  char *target = mmap(NULL, len, PROT_WRITE, MAP_SHARED, fd, 0);
  if (target == MAP_FAILED) {
    perror("Could not map memory");
    return -1;
  }
  int result;
  PROP_ERR(result = write_random_data(target, len));
  PROP_ERR(munmap(target, len));
  return result;
}

int init_and_get_session_mask_fd() {
  static int session_xor_mask = -1;
  if (session_xor_mask == -1) {
    int fd = memfd_secret(O_CLOEXEC);
    if (fd == -1) {
      perror("Couldn't create session mask");
      return -1;
    }
    if (ftruncate(fd, SECRET_LEN) == -1) {
      perror("Couldn't allocate session mask");
      return -1;
    }
    char *target = mmap(NULL, SECRET_LEN, PROT_WRITE, MAP_SHARED, fd, 0);
    if (write_random_data(target, SECRET_LEN) == -1) {
      perror("write_random_data()");
      return -1;
    }
    if (munmap(target, SECRET_LEN) == -1) {
      perror("munmap()");
      return -1;
    }
    session_xor_mask = fd;
  }
  return session_xor_mask;
}

int xor_secret_data(const secret_state_t *data, secret_state_t *output) {
  int mask_fd;
  PROP_ERR(mask_fd = init_and_get_session_mask_fd());
  secret_state_t *key =
      mmap(NULL, sizeof(secret_state_t), PROT_READ, MAP_SHARED, mask_fd, 0);
  if (key == MAP_FAILED) {
    perror("Map mask in xor_secret_data failed");
    return -1;
  }
  unsigned char *out_ptr = *output;
  const unsigned char *data_ptr = *data, *key_ptr = *key;
  for (int i = 0; i < sizeof(secret_state_t); ++i) {
    out_ptr[i] = data_ptr[i] ^ key_ptr[i];
  }
  munmap(key, sizeof(secret_state_t));
  return 0;
}

int xor_secret_data_fd(int source_fd, int destination_fd) {
  secret_state_t *source, *dest;
  source =
      mmap(NULL, sizeof(secret_state_t), PROT_READ, MAP_SHARED, source_fd, 0);
  if (source == MAP_FAILED)
    return -1;
  PROP_ERR(ftruncate(destination_fd, sizeof(secret_state_t)));
  dest = mmap(NULL, sizeof(secret_state_t), PROT_WRITE, MAP_SHARED,
              destination_fd, 0);
  if (dest == MAP_FAILED) {
    munmap(source, SECRET_LEN);
    return -1;
  }
  PROP_ERR(xor_secret_data(source, dest));
  munmap(source, sizeof(secret_state_t));
  munmap(dest, sizeof(secret_state_t));
  return 0;
}

int invalidate_session_secret() {
  if (session_secret_fd != 0) {
    PROP_ERR(close(session_secret_fd));
    session_secret_fd = 0;
  }
  return 0;
}

int get_uid_session_cred_persistant_path_into(uid_t user, char *path,
                                              int max_len) {
  int written = snprintf(path, max_len, PERSISTENT_CREDENTIAL_FORMAT, user);
  if (written >= max_len) {
    return -1;
  } else {
    return written + 1;
  }
}

const char *get_persistant_storage_location() { return PASSWD_DIR; }

const char *get_system_secret_filename() { return SYSTEM_SECRET_FILENAME; }

int get_persistant_storage_fd() {
  static int storage = -1;
  if (storage == -1) {
    PROP_ERR(storage = open(PASSWD_DIR, O_DIRECTORY, 0));
  }
  return storage;
}

const char *get_uid_session_cred_persistant_path(uid_t user) {
  static char path[256];
  if (get_uid_session_cred_persistant_path_into(user, path, ARR_LEN(path)) ==
      -1) {
    return NULL;
  } else {
    return path;
  }
}

int get_uid_session_cred_wrapped_path_into(uid_t user, char *path,
                                           int max_len) {
  int written = snprintf(path, max_len, SESSION_WRAPPED_DIR, user);
  if (written >= max_len) {
    return -1;
  } else {
    return written + 1;
  }
}

const char *get_uid_session_cred_wrapped_path(uid_t user) {
  static char path[256];
  if (get_uid_session_cred_wrapped_path_into(user, path, ARR_LEN(path)) == -1) {
    return NULL;
  } else {
    return path;
  }
}

int get_uid_session_cred_secret_path_into(uid_t user, char *path, int max_len) {
  int written = snprintf(path, max_len, SESSION_WRAPPED_DIR, user);
  if (written >= max_len) {
    return -1;
  } else {
    return written + 1;
  }
}

const char *get_uid_session_cred_secret_path(uid_t user) {
  static char path[256];
  if (get_uid_session_cred_secret_path_into(user, path, ARR_LEN(path)) == -1) {
    return NULL;
  } else {
    return path;
  }
}

// Set secret to a mmaped area where a
int alloc_secret(secret_mem_t *result, int len) {
  result->fd = memfd_secret(O_CLOEXEC);
  result->ptr_len = len;
  // result->fd = memfd_secret(0);
  PROP_ERR(result->fd);
  PROP_ERR(ftruncate(result->fd, len));
  result->ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_SHARED_VALIDATE, result->fd, 0);
  if (result->ptr == MAP_FAILED) {
    return -1;
  }
  return 0;
}

// open_secret_rw(secret_mem_t *secret) {
//
//  secret->ptr = mmap(NULL, secret->ptr_len, PROT_READ | PROT_WRITE,
//                     MAP_ANONYMOUS | MAP_SHARED_VALIDATE, secret->fd, 0);
//  if (secret->ptr == MAP_FAILED) {
//    return -1;
//  }
//  printf("Mapped secret\n");
//  return 0;
//}

int close_secret(secret_mem_t *secret) {
  if (secret->ptr != NULL) {
    void *addrs[] = {secret->ptr};
    PROP_ERR(munmap(addrs, 1));
    secret->ptr = NULL;
  }
  return 0;
}

int free_secret(secret_mem_t *secret) {
  PROP_ERR(close(secret->fd));
  return 0;
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

    // PROP_ERR(add_arg(&curr_arg, end_args, "/usr/bin/bash"));
    // PROP_ERR(add_arg(&curr_arg, end_args, "-c"));
    // PROP_ERR(add_arg(&curr_arg, end_args, "ls -lah /proc/$$/fd/; scrypt
    // \"${@}\""));
    printf("%scrypting data\n", params.op == ENCRYPT ? "En" : "De");
    PROP_ERR(add_arg(&curr_arg, end_args, "/usr/bin/scrypt"));
    PROP_ERR(to_scrypt_args(&params, &curr_arg, end_args));
    PROP_ERR(add_arg(&curr_arg, end_args, "-v"));
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
    if (params.input_is_fd) {
      secret_pipe[tx] = -1;
    } else {
      DEBUG_PROP_ERR(close(secret_pipe[rx]));
    }
    DEBUG_PROP_ERR(close(result_pipe[tx]));
#define CLOSE_NO_ERR(x)                                                        \
  {                                                                            \
    if (x != -1) {                                                             \
      close(x);                                                                \
      x = -1;                                                                  \
    }                                                                          \
  }
#define CLOSE_PIPES                                                            \
  {                                                                            \
    CLOSE_NO_ERR(password_pipe[tx]);                                           \
    CLOSE_NO_ERR(secret_pipe[tx]);                                             \
    CLOSE_NO_ERR(result_pipe[rx]);                                             \
  }
    int epollfd;
    PROP_ERR_WITH(epollfd = epoll_create1(O_CLOEXEC), CLOSE_PIPES);
#define CLOSE_EPOLL                                                            \
  {                                                                            \
    close(epollfd);                                                            \
    CLOSE_PIPES                                                                \
  }
#define PROP_ERR_H(x)                                                          \
  PROP_ERR_WITH(x, {                                                           \
    perror("Failed at " LINE);                                                 \
    CLOSE_EPOLL                                                                \
  })
    int saved_len = 0;
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    if (!params.input_is_fd) {
      ev.data.fd = secret_pipe[tx];
      PROP_ERR_H(epoll_ctl(epollfd, EPOLL_CTL_ADD, secret_pipe[tx], &ev));
    }
    ev.data.fd = password_pipe[tx];
    PROP_ERR_H(epoll_ctl(epollfd, EPOLL_CTL_ADD, password_pipe[tx], &ev));
    ev.events = EPOLLIN;
    ev.data.fd = result_pipe[rx];
    PROP_ERR_H(epoll_ctl(epollfd, EPOLL_CTL_ADD, result_pipe[rx], &ev));
    const int page_size = sysconf(_SC_PAGE_SIZE);
    while (true) {
      struct epoll_event events[5];
      int nfds, c;
      PROP_ERR_H(nfds = epoll_wait(epollfd, events, ARR_LEN(events), -1));
      for (int n = 0; n < nfds; ++n) {
        int is_secret_pipe =
            !params.input_is_fd && events[n].data.fd == secret_pipe[tx];
        if (is_secret_pipe || events[n].data.fd == password_pipe[tx]) {
          const unsigned char **source;
          int *source_len;
          if (is_secret_pipe) {
            source = &params.input.data.ptr;
            source_len = &params.input.data.len;
          } else {
            source = &user_password;
            source_len = &user_password_len;
          }
          PROP_ERR_H(c = write(events[n].data.fd, *source, *source_len));
          if (c == 0) {
            fprintf(stderr, "Could not write complete buffer");
            return -1;
          }
          (*source) += c;
          (*source_len) -= c;
          if (*source_len == 0) {
            PROP_ERR_H(epoll_ctl(epollfd, EPOLL_CTL_DEL, events[n].data.fd,
                                 &events[n]));
            close(events[n].data.fd);
            if (is_secret_pipe) {
              secret_pipe[tx] = -1;
            } else {
              password_pipe[tx] = -1;
            }
          }
        } else if (events[n].data.fd == result_pipe[rx]) {
          int saved_page_offset = saved_len & (page_size - 1);
          if (saved_page_offset == 0) {
            PROP_ERR_H(ftruncate(out_secret_fd,
                                 saved_len - saved_page_offset + page_size));
          }
          char *output =
              mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                   out_secret_fd, saved_len - saved_page_offset);
#define PROP_ERR_M(x)                                                          \
  PROP_ERR_WITH(x, {                                                           \
    munmap(output, page_size);                                                 \
    CLOSE_EPOLL                                                                \
  })
          if (output == MAP_FAILED) {
            perror("Could not map output");
            PROP_ERR_H(-1)
            return -1;
          }
          PROP_ERR_M(c = read(result_pipe[rx], output + saved_page_offset,
                              page_size - saved_page_offset));
          PROP_ERR_H(munmap(output, page_size));
          saved_len += c;
          if (c == 0) {
            int wstatus;
            close(result_pipe[rx]);
            close(epollfd);
            waitpid(child_pid, &wstatus, 0);
            ftruncate(out_secret_fd, saved_len);
            if (!WIFEXITED(wstatus)) {
              char errmsg[256];
              snprintf(errmsg, ARR_LEN(errmsg),
                       "Child process scrypt crashed\n");
              perror(errmsg);
              CLOSE_EPOLL;
              return -1;
            } else if (WEXITSTATUS(wstatus) != 0) {
              CLOSE_EPOLL;
              errno = EACCES;
              return -1;
            } else {
              CLOSE_EPOLL
              return saved_len;
            }
          }
        }
      }
    }
  }
  return -1;
}

int create_user_session_cred_secret(const char *user_password,
                                    int user_password_len) {
  const int rx = PIPE_RX;
  const int tx = PIPE_TX;
  char output_path[256];
  const char *fd_path;
  int generated;
  int storage_fd = get_persistant_storage_fd();
  {
    int output_path_len;
    PROP_ERR(output_path_len = get_uid_session_cred_persistant_path_into(
                 getuid(), output_path, ARR_LEN(output_path)));
    if (faccessat(storage_fd, output_path, F_OK, 0) == 0) {
      errno = EEXIST;
      return -1;
    }
    PROP_ERR(generated =
                 openat(storage_fd, "..", O_TMPFILE | O_CLOEXEC | O_RDWR, 0600));
    char *buf_ptr = output_path + output_path_len;
    fd_path = bufnprintf(&buf_ptr, ARR_END(output_path), "/proc/self/fd/%i",
                         generated);
  }
  int secret_fd;
  PROP_ERR(secret_fd = memfd_secret(O_CLOEXEC));
  PROP_ERR(ftruncate(secret_fd, sizeof(secret_state_t)));
  PROP_ERR(set_memfd_random(secret_fd, sizeof(secret_state_t)));
  secret_state_t *secret_ptr =
      mmap(0, sizeof(secret_state_t), PROT_READ, MAP_SHARED, secret_fd, 0);
  if (secret_ptr == MAP_FAILED) {
    perror("Could not map user secret");
    return -1;
  }
  auto params = set_scrypt_input_data(default_persistent_args(), *secret_ptr,
                                      sizeof(secret_state_t));
  PROP_ERR(scrypt_into_fd(params, (unsigned char*)user_password, user_password_len, generated));
  PROP_ERR(munmap(secret_ptr, SECRET_LEN));
  int umask_before = umask(~0600);
  PROP_ERR(
      linkat(AT_FDCWD, fd_path, storage_fd, output_path, AT_SYMLINK_FOLLOW));
  umask(umask_before);
  close(generated);
  return secret_fd;
}

int get_system_secret_fd() {
    static int fd = -1;
    if (fd == -1) {
        int wd = get_persistant_storage_fd();
        PROP_ERR(fd = openat(wd, get_system_secret_filename(), O_RDONLY | O_CLOEXEC, 0));
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

secret_state_t *alloc_secret_state() {
  if (session_secret_fd == -1) {
    errno = EACCES;
    return NULL;
  }
  secret_state_t *mapped = mmap(NULL, sizeof(secret_state_t), PROT_READ,
                                MAP_SHARED, session_secret_fd, 0);
  if (mapped == MAP_FAILED) {
    return NULL;
  }
  return mapped;
}

int free_secret_state(secret_state_t *mem) {
  char *ptr = *mem;
  return munmap(ptr, sizeof(session_secret_fd));
}

int user_secret_is_unlocked(uid_t user) {
  return access(get_uid_session_cred_secret_path(user), F_OK);
}

int user_wrapped_is_unlocked(uid_t user) {
  return access(get_uid_session_cred_wrapped_path(user), F_OK);
}

int unlock_persistent_user_secret(const char *password, int password_len) {
  uid_t user = getuid();
  int storage_fd, persistant_fd, secret_fd, masked_fd, protected_fd;
  PROP_ERR(storage_fd = get_persistant_storage_fd());
  const int rx = PIPE_RX;
  const int tx = PIPE_TX;
  PROP_ERR(persistant_fd =
               openat(storage_fd, get_uid_session_cred_persistant_path(user),
                      O_CLOEXEC | O_RDONLY));

  scrypt_action_t action = {0};
  action.op = DECRYPT;
  action = set_scrypt_input_fd(action, persistant_fd);
  PROP_ERR(secret_fd = memfd_secret(O_CLOEXEC));
  int secret_len = scrypt_into_fd(action, password, password_len, secret_fd);
  close(persistant_fd);
  if (secret_len != sizeof(secret_state_t)) {
    close(secret_fd);
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
      mmap(NULL, sizeof(secret_state_t), PROT_READ, MAP_SHARED, masked_fd, 0);
  close(masked_fd);
  if (mapped == MAP_FAILED) {
    return -1;
  }
  action = set_scrypt_input_data(default_session_args(), *mapped,
                                 sizeof(secret_state_t));
  PROP_ERR(protected_fd = memfd_secret(O_CLOEXEC));
  int protected_len =
      scrypt_into_fd(action, password, password_len, protected_fd);
  munmap(mapped, sizeof(secret_state_t));
  if (protected_len == -1) {
    close(protected_fd);
    return -1;
  }
  if (session_encrypted_fd != -1) {
    close(session_encrypted_fd);
  }
  session_encrypted_data_len = protected_len;
  session_encrypted_fd = protected_fd;
  return 0;
}

int unlock_plain_user_secret(const char *password, int password_len) {
  if (session_encrypted_fd == -1 || session_encrypted_data_len == 0) {
    errno = ENODATA;
    return -1;
  }
  int secret_fd, protected_fd;
  char *encrypted_data = mmap(NULL, session_encrypted_data_len, PROT_READ,
                              MAP_SHARED, session_encrypted_fd, 0);
  if (encrypted_data == MAP_FAILED) {
    perror("Could not map encrypted data");
    return -1;
  }
  scrypt_action_t action = {0};
  action =
      set_scrypt_input_data(action, encrypted_data, session_encrypted_data_len);
  action.op = DECRYPT;
  PROP_ERR(protected_fd = memfd_secret(O_CLOEXEC));
  int decrypt = scrypt_into_fd(action, password, password_len, protected_fd);
  munmap(encrypted_data, session_encrypted_data_len);
  if (decrypt != sizeof(secret_state_t)) {
    close(protected_fd);
    perror("Could not decrypt");
    return -1;
  }
  PROP_ERR(secret_fd = memfd_secret(O_CLOEXEC));
  PROP_ERR(xor_secret_data_fd(protected_fd, secret_fd));
  close(protected_fd);
  if (session_secret_fd != -1) {
    close(session_secret_fd);
  }
  session_secret_fd = secret_fd;
  return 0;
}

int lock_plain_user_secret() {
  if (session_secret_fd != -1) {
    close(session_secret_fd);
    session_secret_fd = -1;
  }
}

int authenticate_user(const char *password, int password_len) {
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
                       bufnprintf(&args_ptr, buf_end, "%i", work.r)));
      PROP_ERR(add_arg(args, args_end, "-p"));
      PROP_ERR(add_arg(args, args_end,
                       bufnprintf(&args_ptr, buf_end, "%i", work.p)));
    }
    return 0;
  }
  errno = EINVAL;
  return -1;
}
