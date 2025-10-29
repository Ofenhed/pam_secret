#pragma once

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

void hmac(hash_state_t *h, const unsigned char *secret, int secret_len,
          const unsigned char *msg, int msg_len);
void hmac_msg(hash_state_t *h, const unsigned char *msg, int msg_len);

void hmac_finalize(hash_state_t *h, sha256_hash_t *output);
sha256_hash_t *hmac_result(hash_state_t *h);

int hash_init_memfd(int hash_fd, int secret_fd, const unsigned char *msg,
                    int msg_len);

int hash_add(int hash_fd, const unsigned char *msg, int msg_len);

int finalize_hash(int hash_fd, int secret_fd, sha256_hash_t *hash);

sha256_hash_hex_t hash_to_hex(const sha256_hash_t *hash);
