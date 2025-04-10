#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <sys/wait.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("Acct mgmt\n");
    return PAM_SUCCESS;
}

#define ARR_LEN(x) (sizeof(x)/sizeof(x[0]))

static int exec_blocking(const char *prog, char *const argv[]) {
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
        if (execve(prog, argv, NULL) == -1) {
            perror("Child process execve failed");
            return -1;
        }
    }
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
    int retval;

    unsigned int pcr_register = 25;
    for (int i = 0; i < argc; ++i) {
        sscanf(argv[i], "pcr_register=%u", &pcr_register);
    }

    const char* pUsername;
    retval = pam_get_user(pamh, &pUsername, NULL);
    if (retval != PAM_SUCCESS) {
            fprintf(stderr, "Could not get user\n");
        return retval;
    }
    const size_t usernameLen = strlen(pUsername);

    const char* pAuthToken;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pAuthToken, NULL);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Could not read auth token for user %s\n", pUsername);
        return retval;
    }
    const size_t authTokenLen = strlen(pAuthToken);

    char credHash[EVP_MAX_MD_SIZE];
    char resultHash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;

    const unsigned char* pCredHash = HMAC(EVP_sha256(), pAuthToken, authTokenLen, pUsername, usernameLen, (char*)&credHash, &hashLen);
    assert(hashLen == 32);
    if (pCredHash == NULL) {
        fprintf(stderr, "HMAC failed\n");
        return -1;
    }
    const char tpm_hash[] = "TPM PCR Hash";
    const unsigned char* pResultHash = HMAC(EVP_sha256(), pCredHash, hashLen, tpm_hash, ARR_LEN(tpm_hash), (char*)&resultHash, &hashLen);
    assert(hashLen == 32);
    if (pResultHash == NULL) {
        fprintf(stderr, "HMAC failed\n");
        return -1;
    }
    const unsigned char hashOutput[65];
    for (int i = 0; i < 32; ++i) {
        snprintf((char*)(&hashOutput[i<<1]), 3, "%02x", pResultHash[i]);
    }
    char outputBuf[128];
    snprintf((char*)&outputBuf, ARR_LEN(outputBuf), "%u", pcr_register);

    char *const resetArgs[] = {"tpm2_pcrreset", (char*)&outputBuf, NULL};
    if (exec_blocking("/usr/bin/tpm2", resetArgs) == -1) {
        fprintf(stderr, "tpm2_pcrreset failed\n");
        return -1;
    }
    snprintf((char*)&outputBuf, ARR_LEN(outputBuf), "%u:sha256=%s", pcr_register, hashOutput);
    char *const extendArgs[] = {"tpm2_pcrextend", (char*)&outputBuf, NULL};
    if (exec_blocking("/usr/bin/tpm2", extendArgs) == -1) {
        fprintf(stderr, "tpm2_pcrextend failed\n");
        return -1;
    }

    return PAM_SUCCESS;
}
