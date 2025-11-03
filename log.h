#pragma once

void set_default_log_output(int fd);
int get_default_log_output(void);

#define ADD_LOGGER(LEVEL)                                                      \
  void log_##LEVEL(const char *restrict format, ...);                          \
  void vlog_##LEVEL(const char *restrict format, va_list args);                \
  void dlog_##LEVEL(int output, const char *restrict format, ...);             \
  void vdlog_##LEVEL(int output, const char *restrict format, va_list args);   \
  void flog_##LEVEL(FILE *output, const char *restrict format, ...);           \
  void vflog_##LEVEL(FILE *output, const char *restrict format, va_list args);

#include "log_impls.incl"
