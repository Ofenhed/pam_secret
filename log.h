#pragma once

void log_debug(const char *restrict format, ...);

#define ADD_LOGGER(LEVEL) void log_##LEVEL(const char *restrict format, ...);

ADD_LOGGER(debug)
ADD_LOGGER(warning)
ADD_LOGGER(error)
