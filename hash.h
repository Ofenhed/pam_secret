#include <openssl/evp.h>

#define HASH_LEN 32

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
    int active_buf;
    unsigned char hashBuffers[2][EVP_MAX_MD_SIZE];
} hash_state_t;

void hmac(hash_state_t *h, const unsigned char *secret, int secret_len, const unsigned char *msg, int msg_len);

int hash_init_memfd(int hash_fd, int secret_fd, const unsigned char *msg, int msg_len);

int hash_add(int hash_fd, const unsigned char *msg, int msg_len);

int finalize_hash(int hash_fd, int secret_fd, sha256_hash_t *hash);

sha256_hash_hex_t hash_to_hex(const sha256_hash_t *hash);
