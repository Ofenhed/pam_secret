#pragma once

#include <unistd.h>
#include <sys/types.h>

gid_t manager_group();
const char *manager_group_name();
const char *get_persistant_storage_location();
const char *get_system_secret_filename();
int get_persistant_storage_fd();
int get_session_secret_fd();
int get_system_secret_fd();
const char *get_uid_session_cred_persistant_path(uid_t user);
const char *get_uid_session_cred_wrapped_path(uid_t user);
const char *get_uid_session_cred_secret_path(uid_t user);

#ifdef SECRET_LEN_OVERRIDE
#define SECRET_LEN SECRET_LEN_OVERRIDE
#else
#ifndef SECRET_LEN
#define SECRET_LEN 256
#endif
#endif

typedef unsigned char secret_state_t[SECRET_LEN];

typedef struct {
    char* ptr;
    int ptr_len;
    int fd;
} secret_mem_t;

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

int scrypt_into_fd(scrypt_action_t params, const unsigned char *user_password, int user_password_len, int out_secret_fd);
scrypt_action_t set_scrypt_input_data(scrypt_action_t params, const unsigned char *secret, int secret_len);
scrypt_action_t set_scrypt_input_fd(scrypt_action_t params, int fd);
int authenticate_user(const char *password, int password_len);
int lock_plain_user_secret();

int free_secret_state(secret_state_t *fd);
secret_state_t *alloc_secret_state();

int memfd_secret2(int len, int flags);
char *mmap_secret(int fd, int len, int prot);
int munmap_secret(int fd, char *mapped);
int set_memfd_random(int fd, int len);

int alloc_secret(secret_mem_t *result, int len);
int free_secret(secret_mem_t *secret);

int to_scrypt_args(scrypt_action_t *params, const char ***args, const char **args_end);

scrypt_action_t default_persistent_args();
scrypt_action_t default_session_args();

int install_user_session_cred_secret(int source_fd);
int create_user_persistent_cred_secret(int secret_fd, const char *user_password, int user_password_len, int persistent_fd);

int init_and_get_session_mask_fd();
const char *init_and_get_session_mask();
