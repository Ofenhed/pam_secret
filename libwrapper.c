#include <dlfcn.h>

int main(int argc, char **argv) {
  void *pam_mod;
#ifdef DEBUG
  if ((pam_mod = dlopen("build/pam_secret.so", RTLD_NOW)) == 0)
#endif
    pam_mod = dlopen("/usr/lib64/security/pam_secret.so", RTLD_NOW);
  int (*lib_main)(int, char **) = dlsym(pam_mod, "exported_main");
  return lib_main(argc, argv);
}
