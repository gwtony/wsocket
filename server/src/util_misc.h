#ifndef UTIL_MISC_H
#define UTIL_MISC_H

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#endif

