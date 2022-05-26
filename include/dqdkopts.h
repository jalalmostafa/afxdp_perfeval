#ifndef DQDK_OPTS_H
#define DQDK_OPTS_H

#include "datatypes.h"

struct dqdk_opts {
    u32 payload_size;               /* poll memory size to allocate */
    u32 poll_timeout;               /* poll timeout in milliseconds */
    u32 sg_entries;                 /* number of entries/packets to gather before scattering */
};

#endif
