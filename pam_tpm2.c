#include <assert.h>
#include <openssl/hmac.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define ARR_LEN(x) (sizeof(x) / sizeof(x[0]))
#ifndef SUDO_BIN
#define SUDO_BIN "/usr/bin/sudo"
#endif

static int exec_blocking(const char *prog, const char *argv[]) {
  pid_t child = fork();
  if (child == -1) {
    perror("Fork failed");
    return -1;
  } else if (child != 0) {
    int wstatus;
    waitpid(child, &wstatus, 0);
    if (!WIFEXITED(wstatus)) {
      fprintf(stderr, "Child process %s crashed\n", prog);
      return -1;
    } else {
      return WEXITSTATUS(wstatus);
    }
  } else {
    fclose(stdin);
    if (execve(prog, (char *const *)argv, NULL) == -1) {
      perror("Child process execve failed");
      return -1;
    }
  }
}

static int tpm_function(const char *sudoUser, const char *exec,
                        const char *argument) {
  if (sudoUser == NULL) {
    sudoUser = "tss";
  }
  const char *tpmArgs[] = {SUDO_BIN, "-u",     sudoUser, "--",
                           exec,     argument, NULL};
  return exec_blocking(SUDO_BIN, tpmArgs);
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  int retval;

  const char *pUsername;
  retval = pam_get_user(pamh, &pUsername, NULL);
  if (retval != PAM_SUCCESS) {
    fprintf(stderr, "Could not get user\n");
    return retval;
  }
  const size_t usernameLen = strlen(pUsername);

  const char *sudoUser = NULL;
  int pcrRegister = -1;
  int tmpRegister;
  int count;
  for (int i = 0; i < argc; ++i) {
    int separator = -1;
    if (sscanf(argv[i], "pcr_%u=%n", &tmpRegister, &separator) &&
        separator != -1) {
      if (strcmp(argv[i] + separator, pUsername) == 0) {
        pcrRegister = tmpRegister;
      }
    } else if (sscanf(argv[i], "as_user=%n", &separator) == 0 &&
               separator != -1) {
      sudoUser = argv[i] + separator;
    }
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

  char credHash[EVP_MAX_MD_SIZE];
  char resultHash[EVP_MAX_MD_SIZE];
  unsigned int hashLen;

  const unsigned char *pCredHash =
      HMAC(EVP_sha256(), pAuthToken, authTokenLen, (unsigned char *)pUsername, usernameLen,
           (unsigned char *)&credHash, &hashLen);
  assert(hashLen == 32);
  if (pCredHash == NULL) {
    fprintf(stderr, "HMAC failed\n");
    return PAM_SUCCESS;
  }
  const char tpm_hash[] = "TPM PCR Hash";
  const unsigned char *pResultHash =
      HMAC(EVP_sha256(), pCredHash, hashLen, tpm_hash, ARR_LEN(tpm_hash),
           (char *)&resultHash, &hashLen);
  assert(hashLen == 32);
  if (pResultHash == NULL) {
    fprintf(stderr, "HMAC failed\n");
    return PAM_SUCCESS;
  }
  const unsigned char hashOutput[65];
  for (int i = 0; i < 32; ++i) {
    snprintf((char *)(&hashOutput[i << 1]), 3, "%02x", pResultHash[i]);
  }
  char outputBuf[128];
  snprintf((char *)&outputBuf, ARR_LEN(outputBuf), "%u", pcrRegister);

  if (tpm_function(sudoUser, "/usr/bin/tpm2_pcrreset", (char *)&outputBuf) ==
      -1) {
    fprintf(stderr, "tpm2_pcrreset failed\n");
    return PAM_SUCCESS;
  }
  snprintf((char *)&outputBuf, ARR_LEN(outputBuf), "%u:sha256=%s", pcrRegister,
           hashOutput);
  if (tpm_function(sudoUser, "/usr/bin/tpm2_pcrextend", outputBuf) == -1) {
    fprintf(stderr, "tpm2_pcrextend failed\n");
    return PAM_SUCCESS;
  }

  return PAM_SUCCESS;
}
