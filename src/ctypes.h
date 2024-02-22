#ifndef DQDK_CTYPES
#define DQDK_CTYPES

#include <linux/types.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define always_inline inline __attribute__((always_inline))
#define packed __attribute__((packed))

#define IGN_ARG(x) ((void)(x))

#endif
