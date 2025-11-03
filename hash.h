#pragma once

#include "attributes.h"
#include <openssl/evp.h>

#define HASH_LEN 32

static const unsigned char HASH_TYPE_STORAGE_ENCRYPTION_KEY[] =
    "Storage Encryption Key";
static const unsigned char HASH_TYPE_HMAC_REQUEST[] =
    "Hashed Authenticated Messages Head";
static const unsigned char HASH_TYPE_AUTHENTICATED_HMAC_REQUEST[] =
    "Hashed Messages Head";
static const unsigned char HASH_TYPE_MAP_AUTH_TOKEN[] = "Hashed Messages End";
static const unsigned char HASH_TYPE_USER_PASSWORD[] =
    "User Authentication Token";

typedef unsigned char sha256_hash_t[32];
typedef struct {
  union {
    unsigned char printable[65];
    struct {
      unsigned char hash[64];
      unsigned char null;
    };
  };
} sha256_hash_hex_t;

typedef struct {
  unsigned char hash_buffers[2][EVP_MAX_MD_SIZE];
  int active_buf;
} hash_state_t;

void hmac(hash_state_t *h, const unsigned char *secret, size_t secret_len,
          const unsigned char *msg,
          size_t msg_len) __gcc_attribute__((nonnull_if_nonzero(2, 3)))
    __gcc_attribute__((nonnull_if_nonzero(4, 5))) __attribute__((nonnull(1)));

void hmac_msg(hash_state_t *h, const unsigned char *msg, size_t msg_len)
    __gcc_attribute__((nonnull_if_nonzero(2, 3))) __attribute__((nonnull(1)));

void hmac_finalize(hash_state_t *h, sha256_hash_t *output)
    __gcc_attribute__((access(read_only, 1)))
        __gcc_attribute__((access(write_only, 2)))
            __attribute__((nonnull(1), nonnull(2)));

sha256_hash_t *hmac_result(hash_state_t *h) __attribute__((nonnull, pure));

int hash_init_memfd(int hash_fd, int secret_fd, const unsigned char *msg,
                    size_t msg_len) __gcc_attribute__((fd_arg_write(1)))
    __gcc_attribute__((fd_arg_read(2)));

int hash_add(int hash_fd, const unsigned char *msg, size_t msg_len)
    __gcc_attribute__((nonnull_if_nonzero(2, 3)))
        __gcc_attribute__((fd_arg(1)));

int finalize_hash(int hash_fd, int secret_fd, sha256_hash_t *hash)
    __attribute__((nonnull(3))) __gcc_attribute__((access(write_only, 3)))
        __gcc_attribute__((fd_arg(1))) __gcc_attribute__((fd_arg_read(2)));

sha256_hash_hex_t hash_to_hex(const sha256_hash_t *hash) __gcc_attribute__((access(read_only, 1)));
