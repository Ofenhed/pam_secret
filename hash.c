#include "hash.h"
#include "creds.h"
#include "extern.h"
#include "utils.h"
#include <assert.h>
#include <openssl/hmac.h>
#include <string.h>
#include <sys/mman.h>

#ifdef DEBUG_DUMP_HASHING
static void print_sized(const char *var, int length) {
  const char *const end = var + length;
  printf("\"");
  while (var < end) {
    if (*var >= 32 && *var < 128) {
      printf("%c", *var);
    } else {
      printf("\\x%02x", (uint8_t)*var);
    }
    ++var;
  }
  printf("\"");
}
#endif

void hmac(hash_state_t *h, const unsigned char *secret, int secret_len,
          const unsigned char *msg, int msg_len) {
  unsigned int hash_len;
  HMAC(EVP_sha256(), secret, secret_len, msg, msg_len,
       h->hash_buffers[h->active_buf ^= 1], &hash_len);
#ifdef DEBUG_DUMP_HASHING
  printf("HMAC(");
  print_sized((char *)secret, secret_len);
  printf(", ");
  print_sized((char *)msg, msg_len);
  printf(") = ");
  print_sized((char *)h->hash_buffers[h->active_buf], sizeof(sha256_hash_t));
  printf("\n");
#endif
  assert(hash_len == sizeof(sha256_hash_t));
}

void hmac_msg(hash_state_t *h, const unsigned char *msg, int msg_len) {
  hmac(h, h->hash_buffers[h->active_buf], sizeof(sha256_hash_t), msg, msg_len);
}

void hmac_finalize(hash_state_t *h, sha256_hash_t *output) {
  memcpy(output, h->hash_buffers[h->active_buf], sizeof(*output));
}

sha256_hash_t *hmac_result(hash_state_t *h) {
  return (sha256_hash_t *)h->hash_buffers[h->active_buf];
}

sha256_hash_t *mmapped_hmac_result(hash_state_t *h) {
  if (h->active_buf) {
    memcpy(h->hash_buffers[0], h->hash_buffers[1], sizeof(sha256_hash_t));
  }
  assert(offsetof(hash_state_t, hash_buffers) == 0);
  return (sha256_hash_t *)h->hash_buffers[0];
}

int hash_init_memfd(int hash_fd, int secret_fd, const unsigned char *msg,
                    int msg_len) {
  PROP_ERR_WITH(ftruncate(hash_fd, sizeof(hash_state_t)), close(hash_fd););
  hash_state_t *h = mmap(NULL, sizeof(hash_state_t), PROT_READ | PROT_WRITE,
                         MAP_SHARED, hash_fd, 0);
  if (h == MAP_FAILED) {
    return -1;
  }
  secret_state_t *secret =
      mmap(NULL, sizeof(secret_state_t), PROT_READ, MAP_SHARED, secret_fd, 0);
  if (secret == MAP_FAILED) {
    munmap(h, sizeof(hash_state_t));
    return -1;
  }
  hmac(h, *secret, sizeof(secret_state_t), msg, msg_len);
  munmap(secret, sizeof(secret_state_t));
  munmap(h, sizeof(hash_state_t));

  return 0;
}

int hash_add(int hash_fd, const unsigned char *msg, int msg_len) {
  hash_state_t *h = mmap(NULL, sizeof(hash_state_t), PROT_READ | PROT_WRITE,
                         MAP_SHARED, hash_fd, 0);
  if (h == MAP_FAILED) {
    return -1;
  }
  hmac(h, h->hash_buffers[h->active_buf], sizeof(sha256_hash_t), msg, msg_len);
  munmap(h, sizeof(hash_state_t));
  return 0;
}

int finalize_hash(int hash_fd, int secret_fd, sha256_hash_t *result) {
  hash_state_t *h = mmap(NULL, sizeof(hash_state_t), PROT_READ | PROT_WRITE,
                         MAP_SHARED, hash_fd, 0);
  if (h == MAP_FAILED) {
    return -1;
  }
  secret_state_t *secret =
      mmap(NULL, sizeof(secret_state_t), PROT_READ, MAP_SHARED, secret_fd, 0);
  if (secret == MAP_FAILED) {
    munmap(h, sizeof(hash_state_t));
    return -1;
  }
  unsigned int len = sizeof(sha256_hash_t);
  HMAC(EVP_sha256(), secret, sizeof(secret_state_t),
       h->hash_buffers[h->active_buf], sizeof(sha256_hash_t), *result, &len);
  assert(len == sizeof(sha256_hash_t));
  munmap(secret, sizeof(secret_state_t));
  munmap(h, sizeof(hash_state_t));
  return 0;
}

sha256_hash_hex_t hash_to_hex(const sha256_hash_t *result) {
  sha256_hash_hex_t hashOutput;
  char *out_ptr = (char *)hashOutput.hash;
  char *in_ptr = (char *)*result;
  for (int i = 0; i < 32; ++i) {
    snprintf(&out_ptr[i << 1], 3, "%02x", in_ptr[i] & 0xff);
  }
  hashOutput.null = 0;
  return hashOutput;
}
