#pragma once

#include "attributes.h"
#include "hash.h"
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

gid_t manager_group();
const char *manager_group_name();
const char *get_persistent_storage_location();
const char *get_system_secret_filename();
int get_persistent_storage_fd();
int get_persistent_secret_fd(uid_t user);
int open_persistent_secret_fd(uid_t user);
int get_persistent_secret_path_fd(uid_t user);
int get_session_secret_fd();
int get_system_secret_fd();
const char *get_persistent_secret_filename(uid_t user);

static const uid_t INVALID_USER = UINT_MAX;
static const gid_t INVALID_GROUP = UINT_MAX;

#ifdef SECRET_LEN_OVERRIDE
#define SECRET_LEN SECRET_LEN_OVERRIDE
#else
#ifndef SECRET_LEN
#define SECRET_LEN 256
#endif
#endif
#define MAX_PASSWORD_LENGTH 64

typedef unsigned char secret_state_t[SECRET_LEN];

typedef struct {
  float maxtime;
  long maxmem;
  float maxmemfrac;
} scrypt_params_local_t;

typedef struct {
  int n;
  long r;
  float p;
} scrypt_params_work_t;

typedef struct {
  bool is_local;
  union {
    scrypt_params_local_t local;
    scrypt_params_work_t work;
  } params;
} scrypt_params_t;

typedef enum {
  ENCRYPT,
  DECRYPT,
} scrypt_operation_t;

typedef struct {
  scrypt_operation_t op;
  bool input_is_fd;
  union {
    struct {
      const unsigned char *ptr;
      int len;
    } data;
    int fd;
  } input;
  union {
    scrypt_params_t enc_params;
    int dec_params;
  };
} scrypt_action_t;

secret_state_t *map_session_cred() __attr_malloc__(munmap, 1)
    __attribute__((warn_unused_result));
int scrypt_into_fd(scrypt_action_t params, const unsigned char *user_password,
                   int user_password_len, int out_secret_fd)
    __gcc_attribute__((fd_arg_write(4))) __attribute__((warn_unused_result));
scrypt_action_t set_scrypt_input_data(scrypt_action_t params,
                                      const unsigned char *secret,
                                      int secret_len);
scrypt_action_t set_scrypt_input_fd(scrypt_action_t params, int fd)
    __gcc_attribute__((fd_arg_read(2)));
int authenticate_user(const unsigned char *password, int password_len)
    __attribute__((warn_unused_result));
int lock_plain_user_secret();

int set_memfd_random(int fd, int len) __attribute__((warn_unused_result));

int to_scrypt_args(scrypt_action_t *params, const char ***args,
                   const char **args_end)
    __gcc_attribute__((access(read_only, 1)))
        __gcc_attribute__((access(write_only, 2)))
            __attribute__((nonnull(1, 2, 3)))
            __attribute__((warn_unused_result));

scrypt_action_t default_trivial_args();
scrypt_action_t default_persistent_args();
scrypt_action_t default_session_args();

int install_user_session_cred_secret(int source_fd, uid_t user,
                                     int allow_create)
    __gcc_attribute__((fd_arg_read(1))) __attribute__((warn_unused_result));
int create_user_persistent_cred_secret(int secret_fd,
                                       const unsigned char *user_password,
                                       int user_password_len, int persistent_fd)
    __gcc_attribute__((nonnull_if_nonzero(2, 3)))
        __gcc_attribute__((fd_arg_read(1))) __gcc_attribute__((fd_arg_write(4)))
            __attribute__((warn_unused_result));

int hashed_user_cred(const unsigned char *restrict user_password,
                     int user_password_len, sha256_hash_t *output)
    __gcc_attribute__((nonnull_if_nonzero(1, 2))) __attribute__((nonnull(3)))
    __gcc_attribute__((access(write_only, 3)))
        __attribute__((warn_unused_result));
int pam_translated_user_auth_token(const unsigned char *user_password,
                                   int user_password_len, sha256_hash_t *output)
    __gcc_attribute__((nonnull_if_nonzero(1, 2))) __attribute__((nonnull(3)))
    __gcc_attribute__((access(write_only, 3)))
        __attribute__((warn_unused_result));
