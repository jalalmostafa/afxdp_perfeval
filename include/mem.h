#ifndef DQDK_MEM_ALLOCATOR_H
#define DQDK_MEM_ALLOCATOR_H

#include <sys/uio.h>
#include <sys/mman.h>

#include "datatypes.h"

struct dqdk_iovec {
    u32 frame_size;
    u32 nb_entries;
    u32 used_entries;
    struct iovec* vectors;
    struct iovec* head;
};

struct dqdk_iovec* dqdk_iovec_init(u32 frame_size, u32 count);
int dqdk_iovec_free(struct dqdk_iovec* vec);
struct iovec* dqdk_iovec_alloc_entry(struct dqdk_iovec* vec);
int dqdk_iovec_clear(struct dqdk_iovec* vec);
int dqdk_iovec_is_full(struct dqdk_iovec* vec);
int dqdk_iovec_is_empty(struct dqdk_iovec* vec);

#define DQDK_BUFFER_ALLOC(size) (mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0))

#endif
