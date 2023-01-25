// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
// FROM: https://github.com/NetSys/bess/blob/1d8f708fec00e14cf1d840adebd588a8137dcac8/core/utils/checksum.h

#ifndef DQDK_INET_CSUM_SIMD_H
#define DQDK_INET_CSUM_SIMD_H

#include <x86intrin.h>

always_inline inline uint64_t m128i_extract_u64(__m128i a, int i)
{
#if __x86_64

    // While this looks silly, otherwise g++ will complain on -O0
    if (i == 0) {
        return _mm_extract_epi64(a, 0);
    } else {
        return _mm_extract_epi64(a, 1);
    }
#else
    // In 32-bit machines, _mm_extract_epi64() is not supported
    union {
        __m128i vec;
        uint64_t b[2];
    };

    vec = a;
    return b[i];
#endif
}

always_inline u32 udp_csum_avx2(const u16* udp_pkt, u32 len)
{
    const uint64_t* buf64 = (const uint64_t*)udp_pkt;
    uint64_t sum64 = 0;
    bool odd = len & 1;
    const __m256i* buf256 = (const __m256i*)buf64;
    __m256i zero256 = _mm256_setzero_si256();

    // We parallelize two ymm streams to minimize register dependency:
    //     a: buf256,             buf256 + 2,             ...
    //     b:         buf256 + 1,             buf256 + 3, ...
    __m256i a = _mm256_loadu_si256(buf256);
    __m256i b = _mm256_loadu_si256(buf256 + 1);

    // For each stream, accumulate unpackhi and unpacklo in parallel
    // (as 4x64bit vectors, so that each upper 0000 can hold carries)
    // -------------------------------------------------------------------
    // 32B data: aaaaAAAA bbbbBBBB ccccCCCC ddddDDDD  (1 letter = 1 byte)
    // unpackhi: bbbb0000 BBBB0000 dddd0000 DDDD0000
    // unpacklo: aaaa0000 AAAA0000 cccc0000 CCCC0000
    __m256i sum_a_hi = _mm256_unpackhi_epi32(a, zero256);
    __m256i sum_a_lo = _mm256_unpacklo_epi32(a, zero256);
    __m256i sum_b_hi = _mm256_unpackhi_epi32(b, zero256);
    __m256i sum_b_lo = _mm256_unpacklo_epi32(b, zero256);

    len -= sizeof(__m256i) * 2;
    buf256 += 2;

    while (len >= sizeof(__m256i) * 2) {
        a = _mm256_loadu_si256(buf256);
        b = _mm256_loadu_si256(buf256 + 1);

        sum_a_hi = _mm256_add_epi64(sum_a_hi, _mm256_unpackhi_epi32(a, zero256));
        sum_a_lo = _mm256_add_epi64(sum_a_lo, _mm256_unpacklo_epi32(a, zero256));
        sum_b_hi = _mm256_add_epi64(sum_b_hi, _mm256_unpackhi_epi32(b, zero256));
        sum_b_lo = _mm256_add_epi64(sum_b_lo, _mm256_unpacklo_epi32(b, zero256));

        len -= sizeof(__m256i) * 2;
        buf256 += 2;
    }

    // fold four 256bit sums into one 128bit sum
    __m256i sum256 = _mm256_add_epi64(_mm256_add_epi64(sum_a_hi, sum_a_lo),
        _mm256_add_epi64(sum_b_hi, sum_b_lo));
    __m128i sum128 = _mm_add_epi64(_mm256_extracti128_si256(sum256, 0),
        _mm256_extracti128_si256(sum256, 1));

    // fold 128bit sum into 64bit
    sum64 += m128i_extract_u64(sum128, 0) + m128i_extract_u64(sum128, 1);
    buf64 = (const uint64_t*)(buf256);

    const uint16_t* buf16 = (const uint16_t*)(buf64);
    while (len >= sizeof(uint16_t)) {
        sum64 += *buf16++;
        len -= sizeof(uint16_t);
    }

    // Add remaining 8-bit to the one's complement sum
    if (odd) {
        sum64 += *(const uint8_t*)(buf16);
    }

    sum64 = (sum64 >> 32) + (sum64 & 0xFFFFFFFF);
    sum64 += (sum64 >> 32);

    return (uint32_t)(sum64);
}

#endif
