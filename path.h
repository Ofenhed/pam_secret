#include <sys/types.h>
int get_proc_self_fd();
int get_proc_self_fds_fd();

extern const char *persistent_storage_location;
extern const char *system_secret_filename;
extern const char *persistent_credential_request_prefix;

int get_persistent_storage_fd();
int get_persistent_secret_fd(uid_t user);
int open_persistent_secret_fd(uid_t user);
int get_persistent_secret_path_fd(uid_t user);
int get_session_secret_fd();
int get_system_secret_fd();
const char *get_persistent_secret_filename(uid_t user);
