/** @file sb_sha256.c
 *  @brief a compact implementation of SHA-256
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is part of Sweet B, a safe, compact, embeddable library for
 * elliptic curve cryptography.
 *
 * https://github.com/westerndigitalcorporation/sweet-b
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "sb_test.h"
#include "sb_sha256.h"
#include "sb_error.h" // for SB_NULLIFY
#include <string.h>

#define SB_SHA256_ROUNDS 64
#define SB_SHA256_WORD_BITS 32
#define SB_SHA256_WORD_SHIFT 2
#define SB_SHA256_LENGTH_BYTES 8

// see RFC 6234 for the definitions used here

static const sb_sha256_ihash_t sb_sha256_init_state = {
    .v = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    }
};

static const sb_sha256_word_t K[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

// BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
#define BSIG0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))

// BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
#define BSIG1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))

// SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
#define SSIG0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))

// SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
#define SSIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

static inline sb_sha256_word_t sb_sha256_word
    (const sb_byte_t p[static const sizeof(sb_sha256_word_t)])
{
    return ((sb_sha256_word_t) p[0] << 24u) |
           ((sb_sha256_word_t) p[1] << 16u) |
           ((sb_sha256_word_t) p[2] << 8u) |
           ((sb_sha256_word_t) p[3]);
}

static inline void sb_sha256_word_set
    (sb_byte_t p[static const sizeof(sb_sha256_word_t)],
     sb_sha256_word_t const w)
{
    p[0] = (sb_byte_t) (w >> 24u);
    p[1] = (sb_byte_t) (w >> 16u);
    p[2] = (sb_byte_t) (w >> 8u);
    p[3] = (sb_byte_t) w;
}

// SHR^n(x) = x>>n
#define SHR(n, x) ((x) >> (n))

// ROTR^n(x) = (x>>n) OR (x<<(w-n))
#define ROTR(n, x) (SHR(n, x) | ((x) << (SB_SHA256_WORD_BITS - (n))))

// CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
#define CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

// MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))

static inline void sb_sha2_uint64_set
    (sb_byte_t p[static const sizeof(uint64_t)], uint64_t const w)
{
    p[0] = (sb_byte_t) (w >> 56);
    p[1] = (sb_byte_t) (w >> 48);
    p[2] = (sb_byte_t) (w >> 40);
    p[3] = (sb_byte_t) (w >> 32);
    p[4] = (sb_byte_t) (w >> 24);
    p[5] = (sb_byte_t) (w >> 16);
    p[6] = (sb_byte_t) (w >> 8);
    p[7] = (sb_byte_t) w;
}

static void sb_sha256_process_block
    (sb_sha256_state_t sha[static const 1],
     const sb_byte_t M_i[static const SB_SHA256_BLOCK_SIZE])
{
    size_t t;

    sha->a_h = sha->ihash;

    for (t = 0; t < SB_SHA256_ROUNDS; t++) {
        sb_sha256_word_t Wt;

        // in the standard, W is a 64-word message schedule, of which at most
        // the sixteen values starting at t - 16 are used in any given iteration
        // here, W is a rotating window of 16 values
        if (t < 16) {
            Wt = sb_sha256_word(&M_i[t << SB_SHA256_WORD_SHIFT]);
            sha->W[t] = Wt;
        } else {

            // Read W_i as "W(t - i)"
#define W_i(i) (sha->W[((16 - (i)) + t) % 16])

            // Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
            Wt = SSIG1(W_i(2)) + W_i(7) + SSIG0(W_i(15)) + W_i(16);

            W_i(0) = Wt;
        }

        // Read A_H(i) as 'a' + i (for example, A_H(4) is e)
#define A_H(i) (sha->a_h.v[((i) + (64 - t)) % 8])
        const sb_sha256_word_t T1 = A_H(7) +
                                    BSIG1(A_H(4)) +
                                    CH(A_H(4), A_H(5), A_H(6)) +
                                    K[t] + Wt;

        const sb_sha256_word_t T2 = BSIG0(A_H(0)) +
                                    MAJ(A_H(0), A_H(1), A_H(2));

        // On the next iteration, the a_h window will rotate.
        // A_H(3) will become the new e
        // A_H(7) will become the new h

        A_H(3) += T1; // e = d + T1

        // a = T1 + T2
        A_H(7) = T1 + T2;
    }

    for (t = 0; t < 8; t++) {
        // Compute the intermediate hash value H(i)
        sha->ihash.v[t] += sha->a_h.v[t];
    }
}

void sb_sha256_init(sb_sha256_state_t sha[static const 1])
{
#ifdef SB_TEST_TIS
    // I don't know why, but tis-interpreter hates this.
    memset(sha, 0, sizeof(*sha));
    sha->ihash = sb_sha256_init_state;
#else
    *sha = (sb_sha256_state_t) { .ihash = sb_sha256_init_state };
#endif
}

// Process a buffer of an arbitrary number of bytes
void sb_sha256_update(sb_sha256_state_t sha[static const restrict 1],
                      const sb_byte_t* restrict input,
                      size_t len)
{
    // Indicate that this method's runtime should not depend on
    // the value of input
    sb_poison_input(input, len);

    while (len > 0) {
        const size_t fill = sha->total_bytes % SB_SHA256_BLOCK_SIZE;
        const size_t remaining = SB_SHA256_BLOCK_SIZE - fill;
        const size_t take = (len > remaining) ? remaining : len;
        sha->total_bytes += take;

        if (fill == 0 && take == SB_SHA256_BLOCK_SIZE) {
            sb_sha256_process_block(sha, input);
        } else {
            // This handles the initial (some data in the buffer) case and
            // the final (not enough data for a block) case.
            memcpy(&sha->buffer[fill], input, take);
            if ((sha->total_bytes % SB_SHA256_BLOCK_SIZE) == 0) {
                sb_sha256_process_block(sha, sha->buffer);
            }
        }

        input += take;
        len -= take;
    }
}

static const sb_byte_t sb_sha256_final_bit = 0x80;

// This puts the final hash in ihash, but does not set output.
static void sb_sha256_finish_internal
    (sb_sha256_state_t sha[static const restrict 1])
{
    // Annoyingly, the final SHA2 length needs to be in bits, not bytes.
    const uint64_t total_bits = ((uint64_t) sha->total_bytes) << UINT64_C(3);

    // Add the final "1" bit
    sb_sha256_update(sha, &sb_sha256_final_bit, 1);

    // Add the padding by clearing the remainder of the buffer:
    const size_t fill = sha->total_bytes % SB_SHA256_BLOCK_SIZE;
    const size_t remaining = SB_SHA256_BLOCK_SIZE - fill;
    memset(&sha->buffer[fill], 0, remaining);

    if (remaining < SB_SHA256_LENGTH_BYTES) {
        // The padding will extend into the next block
        sb_sha256_process_block(sha, sha->buffer);
        memset(sha->buffer, 0, SB_SHA256_BLOCK_SIZE);
    }

    sb_sha2_uint64_set(&sha->buffer[SB_SHA256_BLOCK_SIZE - 8], total_bits);

    sb_sha256_process_block(sha, sha->buffer);
}

// Prototype!
void sb_sha256_finish_to_buffer(sb_sha256_state_t sha[static restrict 1]);

// This routine is exposed for sb_sw_lib.c, which uses it for message signing
// and verification.
void sb_sha256_finish_to_buffer(sb_sha256_state_t sha[static const restrict 1])
{
    sb_sha256_finish_internal(sha);

    for (size_t i = 0; i < 8; i++) {
        sb_sha256_word_set(&sha->buffer[i << SB_SHA256_WORD_SHIFT],
                           sha->ihash.v[i]);
    }
}

void sb_sha256_finish(sb_sha256_state_t sha[static const restrict 1],
                      sb_byte_t output[static const restrict SB_SHA256_SIZE])
{
    sb_sha256_finish_internal(sha);

    for (size_t i = 0; i < 8; i++) {
        sb_sha256_word_set(&output[i << SB_SHA256_WORD_SHIFT],
                           sha->ihash.v[i]);
    }

    SB_NULLIFY(sha);
}

void sb_sha256_message(sb_sha256_state_t sha[static const restrict 1],
                       sb_byte_t output[static const restrict SB_SHA256_SIZE],
                       const sb_byte_t* const restrict input,
                       size_t const len)
{
    sb_sha256_init(sha);
    sb_sha256_update(sha, input, len);
    sb_sha256_finish(sha, output);
}

#ifdef SB_TEST

// These are the examples from FIPS 180-2

static const sb_byte_t sb_sha256_test_m1[] = "abc";
static const sb_byte_t sb_sha256_test_m2[] =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"; // what the heck

// TEST_M3 is a million 'a's, which are generated rather than stuck in a static
// const

static const sb_byte_t sb_sha256_test_h1[] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
    0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
};

static const sb_byte_t sb_sha256_test_h2[] = {
    0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
    0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
    0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
    0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1
};

static const sb_byte_t sb_sha256_test_h3[] = {
    0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
    0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
    0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
    0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0
};

_Bool sb_test_sha256_fips_180_2_1(void)
{
    sb_sha256_state_t ctx;
    sb_byte_t hash[SB_SHA256_SIZE];

    sb_sha256_init(&ctx);
    sb_sha256_update(&ctx, sb_sha256_test_m1, sizeof(sb_sha256_test_m1) - 1);
    sb_sha256_finish(&ctx, hash);
    SB_TEST_ASSERT_EQUAL(hash, sb_sha256_test_h1);
    return 1;
}

_Bool sb_test_sha256_fips_180_2_2(void)
{
    sb_sha256_state_t ctx;
    sb_byte_t hash[SB_SHA256_SIZE];

    sb_sha256_message(&ctx, hash,
                      sb_sha256_test_m2, sizeof(sb_sha256_test_m2) - 1);
    SB_TEST_ASSERT_EQUAL(hash, sb_sha256_test_h2);
    return 1;
}

_Bool sb_test_sha256_fips_180_2_3(void)
{
    sb_sha256_state_t ctx;
    sb_byte_t hash[SB_SHA256_SIZE];

    size_t len = 1000000; // one MILLION 'a's
    size_t chunk = 1;
    size_t iter = 0;
    _Bool hit_block_boundary = 0;
    sb_sha256_init(&ctx);
    while (len) {
        sb_byte_t aaaa[128];
        chunk = (chunk * 151) % 128;
        chunk += (iter % 2); // let's stick some even numbers in there too
        if (chunk > len) {
            chunk = len;
        }
        memset(aaaa, 'a', chunk);
        sb_sha256_update(&ctx, aaaa, chunk);
        if ((ctx.total_bytes % SB_SHA256_BLOCK_SIZE) == 0) {
            hit_block_boundary = 1;
        }
        len -= chunk;
        iter++;
    }
    sb_sha256_finish(&ctx, hash);
    SB_TEST_ASSERT_EQUAL(hash, sb_sha256_test_h3);
    SB_TEST_ASSERT(hit_block_boundary);
    return 1;
}

extern _Bool sb_test_sha256_cavp_file(const char* file);

_Bool sb_test_sha256_cavp_file(const char* file)
{
    FILE* tests = NULL;
    size_t count = 0, len;

    sb_test_buf_t message = sb_test_buf_init;
    sb_test_buf_t hash = sb_test_buf_init;

    SB_TEST_ASSERT(sb_test_open(file, &tests));
    SB_TEST_ASSERT(sb_test_advance_to_section(tests, "[L = "
                       SB_TEST_STRINGIFY(SB_SHA256_SIZE)
                       "]"));
    while (sb_test_fetch_next_int(tests, &len)) {
        count++;

        SB_TEST_ASSERT(!(len & 0x7u));

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &message));
        SB_TEST_BYTES_RAW(&message);

        if (len == 0) {
            message.len = 0;
        } else {
            SB_TEST_ASSERT(message.len == (len >> 3u));
        }


        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &hash));
        SB_TEST_BYTES_RAW(&hash);

        sb_sha256_state_t ctx;
        sb_byte_t hash_out[SB_SHA256_SIZE];

        sb_sha256_init(&ctx);
        sb_sha256_update(&ctx, message.buf, message.len);
        sb_sha256_finish(&ctx, hash_out);
        SB_TEST_ASSERT_EQUAL(hash.buf[0], hash_out);
    }

    sb_test_buf_free(&message);
    sb_test_buf_free(&hash);
    fclose(tests);
    return 1;
}

extern _Bool sb_test_sha256_cavp_file_monte(const char* file);

_Bool sb_test_sha256_cavp_file_monte(const char* file)
{
    FILE* tests = NULL;
    size_t count = 0, i = 0;

    sb_test_buf_t seed = sb_test_buf_init;
    sb_test_buf_t hash = sb_test_buf_init;

    SB_TEST_ASSERT(sb_test_open(file, &tests));
    SB_TEST_ASSERT(sb_test_advance_to_section(tests, "[L = "
                       SB_TEST_STRINGIFY(SB_SHA256_SIZE)
                       "]"));

    SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &seed));
    SB_TEST_BYTES_RAW(&seed);
    SB_TEST_ASSERT(seed.len == SB_SHA256_SIZE);

    while (sb_test_fetch_next_int(tests, &count)) {
        SB_TEST_ASSERT(count == i);
        i++;

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &hash));
        SB_TEST_BYTES_RAW(&hash);

        SB_TEST_ASSERT(hash.len == SB_SHA256_SIZE);

        sb_byte_t md[4][SB_SHA256_SIZE];
        sb_byte_t mi[SB_SHA256_SIZE * 3];

        memcpy(md[3], seed.buf, SB_SHA256_SIZE);

        for (size_t j = 0; j < (count + 1); j++) {
            memcpy(md[0], md[3], SB_SHA256_SIZE);
            memcpy(md[1], md[3], SB_SHA256_SIZE);
            memcpy(md[2], md[3], SB_SHA256_SIZE);

            for (size_t c = 3; c < 1003; c++) {
                memcpy(mi, md[0], SB_SHA256_SIZE);
                memcpy(mi + SB_SHA256_SIZE, md[1], SB_SHA256_SIZE);
                memcpy(mi + (SB_SHA256_SIZE * 2), md[2], SB_SHA256_SIZE);

                sb_sha256_state_t ctx;
                sb_sha256_init(&ctx);
                sb_sha256_update(&ctx, mi, SB_SHA256_SIZE * 3);
                memcpy(md[0], md[1], SB_SHA256_SIZE);
                memcpy(md[1], md[2], SB_SHA256_SIZE);
                sb_sha256_finish(&ctx, md[2]);
            }

            memcpy(md[3], md[2], SB_SHA256_SIZE);
        }

        SB_TEST_ASSERT_EQUAL(hash.buf[0], md[3]);
    }

    sb_test_buf_free(&seed);
    sb_test_buf_free(&hash);
    fclose(tests);

    return 1;
}

#endif
