#define ADD_LOGGER(LEVEL)                                                      \
  void log_##LEVEL(const char *restrict format, ...) {                         \
    va_list args;                                                              \
    va_start(args, format);                                                    \
    vfprintf(stderr, ##LEVEL format "\n", args);                               \
    va_end(args)                                                               \
  }
#ifdef DEBUG
#undef ADD_LOGGER
#define ADD_LOGGER(LEVEL)                                                      \
  inline void log_##LEVEL(const char *restrict format, ...) { return; }
#endif

ADD_LOGGER(debug)
ADD_LOGGER(warning)
ADD_LOGGER(error)
