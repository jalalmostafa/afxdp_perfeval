#ifndef TRISTAN_H
#define TRISTAN_H

#include "dqdk.h"

struct energy_evt {
    u16 id;
    u16 channel;
    u32 energy : 24;
    u8 mask;
    u16 trigger_info;
    u64 timestamp : 48;
} packed;

typedef struct energy_evt energy_evt_t;

#define TRISTAN_HISTO_EVT_SZ sizeof(energy_evt_t)

#define HISTO_BINS (2 << 15) // 2^16 bins
#define HISTO_COUNT 8 // usually 5 or 6
#define CHNLS_1TILE 168
#define TILES_COUNT 21
#define CHNLS_COUNT (CHNLS_1TILE * TILES_COUNT)

typedef struct {
    // _Atomic(u32) histograms[HISTO_COUNT][HISTO_BINS];
    u32 histograms[HISTO_COUNT][HISTO_BINS];
} chnl_t;

typedef struct {
    chnl_t channels[CHNLS_COUNT];
} tristan_histo_t;

#define TRISTAN_HISTO_SZ (sizeof(tristan_histo_t))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntoh24b(x) (((x & 0xff) << 16) | (((x >> 8) & 0xff) << 8) | ((x >> 16) & 0xff))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ntoh24b(x) (x)
#else
#error "Unsupported Endianess"
#endif

typedef enum {
    TRISTAN_MODE_RAW,
    TRISTAN_MODE_HISTOGRAM,
} tristan_mode_t;

always_inline int tristan_daq_raw(xsk_info_t* xsk, u8* data, int datalen)
{
    // detector data
    memcpy(xsk->large_mem, data, datalen);
    // rte_memcpy(xsk->large_mem, data, datalen);
    u64* nt_counter = (u64*)data;
    u64 hst_counter = nt_counter[0];

    if (xsk->last_idx != -1) {
        int diff = hst_counter - xsk->last_idx;
        if (diff == 0) {
            printf("dups is %llu\n", hst_counter);
            ++xsk->stats.tristan_dups;
        } else {
            ++xsk->stats.tristan_outoforder;
        }
    }

    xsk->last_idx = hst_counter;

    return 0;
}

always_inline int tristan_daq_histo(tristan_histo_t* histo, xsk_info_t* xsk, u8* data, int datalen)
{
    energy_evt_t* evts = (energy_evt_t*)data;
    int nbevts = datalen / TRISTAN_HISTO_EVT_SZ;
    int last_evt_id = -1;

    xsk->stats.tristan_histogram_evts += nbevts;

    for (int i = 0; i < nbevts; i++) {
        energy_evt_t evt = evts[i];
        // evt->id = ntohs(evt->id);
        // evt->channel = ntohs(evt->channel);
        // evt->energy = ntoh24b(evt->energy);
        int histo_idx = log2l(evt.mask);
        histo->channels[evt.channel].histograms[histo_idx][evt.energy]++;

        if (last_evt_id != -1 && evt.id - last_evt_id > 3)
            xsk->stats.tristan_histogram_lost_evts += evt.id - last_evt_id - 1;

        last_evt_id = evt.id;
    }

    return 0;
}

#endif
