#include "utils.h"
#include <assert.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  return PAM_SUCCESS;
}

//static int tpm_function(const char *sudoUser, const char *exec,
//                        const char *argument) {
//  if (sudoUser == NULL) {
//    sudoUser = "tss";
//  }
//  const char *tpmArgs[] = {AS_USER(sudoUser),
//                           exec,     argument, NULL};
//  return exec_blocking(AS_USER_BIN, tpmArgs);
//}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  int retval;
  int pcrRegister = -1;
  int tmpRegister;

  if (flags & PAM_SILENT) {
    int out = open("/dev/null", O_WRONLY);
    if (out == -1) {
      return PAM_AUTH_ERR;
    }
    dup2(out, STDERR_FILENO);
    dup2(out, STDOUT_FILENO);
    close(out);
  }

  const char *pUsername;
  retval = pam_get_user(pamh, &pUsername, NULL);
  if (retval != PAM_SUCCESS) {
    fprintf(stderr, "Could not get user\n");
    return retval;
  }
  const size_t usernameLen = strlen(pUsername);
  struct passwd *userPwd = getpwnam(pUsername);
  if (userPwd == NULL) {
      fprintf(stderr, "Could not read user info");
      return PAM_AUTH_ERR;
  }

  char persistent_key_path[256] = "";
  char session_key_path[256] = "";
  char secret_key_path[256] = "";
  snprintf(persistent_key_path, ARR_LEN(persistent_key_path), "%s/.config/pam_key", "/home/user");
  snprintf(session_key_path, ARR_LEN(session_key_path), "/var/run/%i/pam_key.session", 1000);
  snprintf(secret_key_path, ARR_LEN(secret_key_path), "/var/run/%i/pam_key.secret", 1000);
  int count;
  for (int i = 0; i < argc; ++i) {
    int separator = -1;
    if (sscanf(argv[i], "pcr_%u=%n", &tmpRegister, &separator) &&
        separator != -1) {
      if (strcmp(argv[i] + separator, pUsername) == 0) {
        pcrRegister = tmpRegister;
      }
    // } else if (sscanf(argv[i], "as_user=%n", &separator) == 0 &&
    //            separator != -1) {
    //   sudoUser = argv[i] + separator;
    }
    sscanf(argv[i], "persistent_key_path=%255s", persistent_key_path);
  }
  if (pcrRegister == -1) {
    return PAM_CRED_INSUFFICIENT;
  }

  const char *pAuthToken;
  retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pAuthToken, NULL);
  if (retval != PAM_SUCCESS) {
    fprintf(stderr, "Could not read auth token for user %s\n", pUsername);
    return retval;
  }
  const size_t authTokenLen = strlen(pAuthToken);

  char hashBuffers[2][EVP_MAX_MD_SIZE];
  size_t nextHash = 0;
  unsigned int hashLen;

  const unsigned char *pResultHash =
      HMAC(EVP_sha256(), pAuthToken, authTokenLen, (unsigned char *)pUsername,
           usernameLen, (unsigned char *)&hashBuffers[nextHash ^= 1], &hashLen);
  assert(hashLen == 32);
  if (pResultHash == NULL) {
    fprintf(stderr, "HMAC failed\n");
    return PAM_AUTH_ERR;
  }
  for (int i = 0; i < argc; ++i) {
    int separator = -1;
    if (sscanf(argv[i], "hmac_msg=%n", &separator) == 0 && separator != -1) {
      const char *msg = argv[i] + separator;
      size_t msgLen = strlen(msg);
      pResultHash =
          HMAC(EVP_sha256(), pResultHash, hashLen, (const unsigned char *)msg,
               msgLen, (unsigned char *)&hashBuffers[nextHash ^= 1], &hashLen);
      assert(hashLen == 32);
    }
  }
  assert(hashLen == 32);
  if (pResultHash == NULL) {
    fprintf(stderr, "HMAC failed\n");
    return PAM_AUTH_ERR;
  }

  // TODO: Check if systemd secret is accessible.
  // Otherwise, check if session encrypted secret is decryptable. If so, encrypt it with systemd-creds against system secret and pcr. This file is intended to exist only when the screen is unlocked.
  // If it's not decryptable, return error.
  // If it doesn't exist, check if the persistent encrypted secret is decryptable by the user's credentials. If so, encrypt it to volatile storage against the user's credentials, with less harsh scrypt parameters than for the  persistant file. This file is intended to be available whenever the user is logged in.
  // If none of those exist, generate a new random blob and encrypt it against the user's credentials using scrypt (TODO: Credentials must be valid, or we're locking the user out) with harsh parameters. This file is intended to always exist. The harsh parameters are meant to be decrypted probably once per computer bootup.
  //
  // All scrypt layers of encryption should probably be followed by a systemd-creds layer, which adds user separation as a layer protecting the file. Probably not a good idea to use TPM to protect the persistent file.
  //
  // When the user is logged out, send random data to the PCR and remove the session ecrypted secret file.

  const unsigned char hashOutput[65];
  for (int i = 0; i < 32; ++i) {
    snprintf((char *)(&hashOutput[i << 1]), 3, "%02x", pResultHash[i]);
  }
  char outputBuf[128];
  snprintf((char *)&outputBuf, ARR_LEN(outputBuf), "%u", pcrRegister);

  //if (tpm_function(sudoUser, "/usr/bin/tpm2_pcrreset", (char *)&outputBuf) !=
  //    0) {
  //  fprintf(stderr, "tpm2_pcrreset failed\n");
  //  return PAM_AUTH_ERR;
  //}
  snprintf((char *)&outputBuf, ARR_LEN(outputBuf), "%u:sha256=%s", pcrRegister,
           hashOutput);
  // if (tpm_function(sudoUser, "/usr/bin/tpm2_pcrextend", outputBuf) != 0) {
  //   fprintf(stderr, "tpm2_pcrextend failed\n");
  //   return PAM_AUTH_ERR;
  // }

  return PAM_SUCCESS;
}
