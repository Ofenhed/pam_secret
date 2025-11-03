#pragma once

#ifdef __clang__
#define __attr_malloc__(FUN, IDX) __attribute__((malloc))
#define __gcc_attribute__(x)
#else
#define __attr_malloc__(FUN, IDX) __attribute__((malloc(FUN, IDX)))
#define __gcc_attribute__(x) __attribute__(x)
#endif

#define EXPORTED __attribute__((visibility("default")))
