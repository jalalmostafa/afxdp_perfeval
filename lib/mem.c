#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include "mem.h"

#define PAGE_SIZE(entry_size, nb_entries) \
    ((entry_size + sizeof(struct iovec)) * nb_entries)

struct dqdk_iovec* dqdk_iovec_init(u32 frame_size, u32 nb_entries)
{
    struct dqdk_iovec* iovec = (struct dqdk_iovec*)calloc(1, sizeof(struct dqdk_iovec));
    iovec->nb_entries = nb_entries;
    iovec->frame_size = frame_size;
    iovec->vectors = DQDK_BUFFER_ALLOC(PAGE_SIZE(frame_size, nb_entries));
    iovec->head = iovec->vectors;
    iovec->used_entries = 0;
}

int dqdk_iovec_free(struct dqdk_iovec* vec)
{
    if (vec != NULL) {
        munmap(vec->vectors, PAGE_SIZE(vec->frame_size, vec->nb_entries));
        free(vec);
        return 1;
    }
    return 0;
}

#define BUFFERS_START(vecs) ((u8*)(vecs->vectors + vecs->nb_entries))
#define BUFFER_ALLOC(vecs) (BUFFERS_START(vecs) + (vecs->used_entries * vecs->frame_size))

inline struct iovec* dqdk_iovec_alloc_entry(struct dqdk_iovec* vecs)
{
    struct iovec* vector = NULL;
    vector = vecs->head;
    vector->iov_base = BUFFER_ALLOC(vecs);
    vector->iov_len = vecs->frame_size;
    vecs->head = vecs->head + 1;
    ++vecs->used_entries;
    return vector;
}

inline int dqdk_iovec_clear(struct dqdk_iovec* vec)
{
    int used = 0;
    if (vec != NULL) {
        used = vec->used_entries;
        vec->used_entries = 0;
        vec->head = vec->vectors;
        return used;
    }
    return 0;
}

inline int dqdk_iovec_is_full(struct dqdk_iovec* vec)
{
    return vec->nb_entries == vec->used_entries;
}

inline int dqdk_iovec_is_empty(struct dqdk_iovec* vec)
{
    return vec->used_entries == 0;
}
