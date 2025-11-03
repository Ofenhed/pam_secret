#include "log.h"
#include "utils.h"

#undef ADD_LOGGER

static int default_log_output = 2;
void set_default_log_output(int fd) { default_log_output = fd; }
int get_default_log_output(void) { return default_log_output; }

#define ADD_LOGGER_BACKEND(LEVEL)                                              \
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
    vdlog_##LEVEL(fileno(output), format, args);                               \
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
#define ADD_NO_LOGGER(LEVEL)                                                   \
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

#if LOG_LEVEL <= 5
#define LOG_LEVEL_5(x) ADD_LOGGER_BACKEND(x)
#else
#define LOG_LEVEL_5(x) ADD_NO_LOGGER(x)
#endif
#if LOG_LEVEL <= 4
#define LOG_LEVEL_4(x) ADD_LOGGER_BACKEND(x)
#else
#define LOG_LEVEL_4(x) ADD_NO_LOGGER(x)
#endif
#if LOG_LEVEL <= 3
#define LOG_LEVEL_3(x) ADD_LOGGER_BACKEND(x)
#else
#define LOG_LEVEL_3(x) ADD_NO_LOGGER(x)
#endif
#if LOG_LEVEL <= 2
#define LOG_LEVEL_2(x) ADD_LOGGER_BACKEND(x)
#else
#define LOG_LEVEL_2(x) ADD_NO_LOGGER(x)
#endif
#if LOG_LEVEL <= 1
#define LOG_LEVEL_1(x) ADD_LOGGER_BACKEND(x)
#else
#define LOG_LEVEL_1(x) ADD_NO_LOGGER(x)
#endif

#define ADD_LOGGER(LEVEL, LEVEL_ID) LOG_LEVEL_##LEVEL_ID(LEVEL)

#include "log_impls.incl"
