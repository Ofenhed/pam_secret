#include "log.h"
#include "utils.h"

#undef ADD_LOGGER

static int default_log_output = 2;
void set_default_log_output(int fd) { default_log_output = fd; }
int get_default_log_output(void) { return default_log_output; }

#define ADD_LOGGER(LEVEL)                                                      \
  void vdlog_##LEVEL(int output, const char *restrict format, va_list args) {  \
    dprintf(output, "%s: ", STRINGIZE_VALUE_OF(LEVEL));                        \
    vdprintf(output, format, args);                                            \
    dprintf(output, "\n");                                                     \
  }                                                                            \
  void dlog_##LEVEL(int output, const char *restrict format, ...) {            \
    va_list args;                                                              \
    va_start(args, format);                                                    \
    vdlog_##LEVEL(output, format, args);                                       \
    va_end(args);                                                              \
  }                                                                            \
  void vflog_##LEVEL(FILE *output, const char *restrict format,                \
                     va_list args) {                                           \
    vdprintf(fileno(output), format, args);                                    \
  }                                                                            \
  void flog_##LEVEL(FILE *output, const char *restrict format, ...) {          \
    va_list args;                                                              \
    va_start(args, format);                                                    \
    vflog_##LEVEL(output, format, args);                                       \
    va_end(args);                                                              \
  }                                                                            \
  void vlog_##LEVEL(const char *restrict format, va_list args) {               \
    vdlog_##LEVEL(get_default_log_output(), format, args);                     \
  }                                                                            \
  void log_##LEVEL(const char *restrict format, ...) {                         \
    va_list args;                                                              \
    va_start(args, format);                                                    \
    vlog_##LEVEL(format, args);                                                \
    va_end(args);                                                              \
  }
#ifndef DEBUG
#undef ADD_LOGGER
#define ADD_LOGGER(LEVEL)                                                      \
  inline void flog_##LEVEL(FILE *output, const char *restrict format, ...) {   \
    return;                                                                    \
  }                                                                            \
  inline void vflog_##LEVEL(FILE *output, const char *restrict format,         \
                            va_list args) {                                    \
    return;                                                                    \
  }                                                                            \
  inline void log_##LEVEL(const char *restrict format, ...) { return; }        \
  inline void vlog_##LEVEL(const char *restrict format, va_list args) {        \
    return;                                                                    \
  }
#endif

#include "log_impls.incl"
