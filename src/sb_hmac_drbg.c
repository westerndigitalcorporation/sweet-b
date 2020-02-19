/** @file sb_hmac_drbg.c
 *  @brief implementation of HMAC-DRBG using SHA-256
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
#include "sb_hmac_drbg.h"
#include <string.h>

// entropy_input || nonce || personalization
#define UPDATE_VECTORS SB_HMAC_DRBG_ADD_VECTOR_LEN

// For use in HMAC-DRBG only; assumes the current key is SB_SHA256_SIZE bytes.
extern void sb_hmac_sha256_finish_to_key(sb_hmac_sha256_state_t hmac[static 1]);

// K = HMAC(K, V || r || provided_data)
// V = HMAC(K, V)
static void sb_hmac_drbg_update_step
    (sb_hmac_drbg_state_t drbg[static const restrict 1],
     const sb_byte_t r[static const 1],
     const sb_byte_t* const provided[static const UPDATE_VECTORS],
     const size_t provided_len[static const UPDATE_VECTORS])
{
    sb_hmac_sha256_reinit(&drbg->hmac);
    sb_hmac_sha256_update(&drbg->hmac, drbg->V, SB_SHA256_SIZE);
    sb_hmac_sha256_update(&drbg->hmac, r, 1);
    for (size_t i = 0; i < UPDATE_VECTORS; i++) {
        if (provided_len[i] > 0) {
            sb_hmac_sha256_update(&drbg->hmac, provided[i],
                                  provided_len[i]);
        }
    }
    sb_hmac_sha256_finish_to_key(&drbg->hmac);
    sb_hmac_sha256_update(&drbg->hmac, drbg->V, SB_SHA256_SIZE);
    sb_hmac_sha256_finish(&drbg->hmac, drbg->V);
}

static void sb_hmac_drbg_update_vec
    (sb_hmac_drbg_state_t drbg[static const restrict 1],
     const sb_byte_t* const provided[static const UPDATE_VECTORS],
     const size_t provided_len[static const UPDATE_VECTORS],
     _Bool any_provided)
{
    static const sb_byte_t r0 = 0x00, r1 = 0x01;
    sb_hmac_drbg_update_step(drbg, &r0, provided, provided_len);
    if (any_provided) {
        sb_hmac_drbg_update_step(drbg, &r1, provided, provided_len);
    }
}

sb_error_t sb_hmac_drbg_reseed(sb_hmac_drbg_state_t
                               drbg[static const restrict 1],
                               const sb_byte_t* const entropy,
                               const size_t entropy_len,
                               const sb_byte_t* const additional,
                               const size_t additional_len)
{
    sb_error_t err = 0;

    if (drbg->reseed_counter == 0) {
        err |= SB_ERROR_DRBG_UNINITIALIZED;
    }

    if (entropy_len < SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH) {
        err |= SB_ERROR_INSUFFICIENT_ENTROPY;
    }

    if (entropy_len > SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH ||
        additional_len > SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH) {
        err |= SB_ERROR_INPUT_TOO_LARGE;
    }

    if (err) {
        return err;
    }

    const sb_byte_t* const a_vec[UPDATE_VECTORS] = {
        entropy, additional, NULL
    };
    const size_t alen_vec[UPDATE_VECTORS] = { entropy_len, additional_len, 0 };
    sb_hmac_drbg_update_vec(drbg, a_vec, alen_vec, 1);
    drbg->reseed_counter = 1;
    return SB_SUCCESS;
}

sb_error_t sb_hmac_drbg_reseed_required(sb_hmac_drbg_state_t const
                                        drbg[static const 1],
                                        const size_t count)
{
    sb_error_t err = 0;

    if (drbg->reseed_counter == 0) {
        err |= SB_ERROR_DRBG_UNINITIALIZED;
    }

    // if drbg->reseed_counter == SB_HMAC_DRBG_RESEED_INTERVAL then the next
    // call to generate will succeed, but the following call will fail
    if (drbg->reseed_counter + count > SB_HMAC_DRBG_RESEED_INTERVAL + 1) {
        err |= SB_ERROR_RESEED_REQUIRED;
    }

    return err;
}

sb_error_t sb_hmac_drbg_init(sb_hmac_drbg_state_t drbg[static const restrict 1],
                             const sb_byte_t* const entropy,
                             size_t const entropy_len,
                             const sb_byte_t* const nonce,
                             size_t const nonce_len,
                             const sb_byte_t* const personalization,
                             size_t const personalization_len)
{
    memset(drbg, 0, sizeof(sb_hmac_drbg_state_t));

    // V is all zeros, which is the initial HMAC key
    sb_hmac_sha256_init(&drbg->hmac, drbg->V, SB_SHA256_SIZE);

    memset(drbg->V, 0x01, SB_SHA256_SIZE);

    sb_error_t err = 0;

    if (entropy_len < SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH ||
        nonce_len < SB_HMAC_DRBG_MIN_NONCE_LENGTH) {
        err |= SB_ERROR_INSUFFICIENT_ENTROPY;
    }

    if (entropy_len > SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH ||
        nonce_len > SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH ||
        personalization_len > SB_HMAC_DRBG_MAX_PERSONALIZATION_STRING_LENGTH) {
        err |= SB_ERROR_INPUT_TOO_LARGE;
    }

    if (err) {
        return err;
    }

    const sb_byte_t* const a_vec[UPDATE_VECTORS] = {
        entropy, nonce, personalization
    };

    const size_t alen_vec[UPDATE_VECTORS] = {
        entropy_len, nonce_len, personalization_len
    };

    sb_hmac_drbg_update_vec(drbg, a_vec, alen_vec, 1);

    drbg->reseed_counter = 1;

    return SB_SUCCESS;
}

static sb_error_t sb_hmac_drbg_generate_additional_vec_opt
    (sb_hmac_drbg_state_t drbg[static const restrict 1],
     sb_byte_t* restrict output, size_t const output_len,
     const sb_byte_t* const additional[static const SB_HMAC_DRBG_ADD_VECTOR_LEN],
     const size_t additional_len[static const SB_HMAC_DRBG_ADD_VECTOR_LEN],
     _Bool const additional_required)
{
    sb_error_t err = 0;

    if (drbg->reseed_counter == 0) {
        err |= SB_ERROR_DRBG_UNINITIALIZED;
    }

    if (output_len > SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST) {
        err |= SB_ERROR_REQUEST_TOO_LARGE;
    }

    size_t total_additional_len = 0;
    for (size_t i = 0; i < SB_HMAC_DRBG_ADD_VECTOR_LEN; i++) {
        total_additional_len += additional_len[i];
    }

    if ((additional_required
#ifdef SB_TEST
        || drbg->additional_input_required
#endif
        )
    && (total_additional_len == 0)) {
        err |= SB_ERROR_ADDITIONAL_INPUT_REQUIRED;
    }

    if (total_additional_len > SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH) {
        err |= SB_ERROR_INPUT_TOO_LARGE;
    }

    if (drbg->reseed_counter > SB_HMAC_DRBG_RESEED_INTERVAL) {
        err |= SB_ERROR_RESEED_REQUIRED;
    }

    if (err) {
        return err;
    }

    if (total_additional_len > 0) {
        sb_hmac_drbg_update_vec(drbg, additional, additional_len,
                                total_additional_len > 0);
    }

    size_t remaining = output_len;

    while (remaining) {
        size_t gen = remaining > SB_SHA256_SIZE ? SB_SHA256_SIZE : remaining;

        sb_hmac_sha256_reinit(&drbg->hmac);
        sb_hmac_sha256_update(&drbg->hmac, drbg->V, SB_SHA256_SIZE);
        sb_hmac_sha256_finish(&drbg->hmac, drbg->V);

        memcpy(output, drbg->V, gen);
        output += gen;
        remaining -= gen;
    }

    sb_hmac_drbg_update_vec(drbg, additional, additional_len,
                            total_additional_len > 0);

    // This increment cannot overflow because SB_HMAC_DRBG_RESEED_INTERVAL is
    // much less than SIZE_MAX, and drbg->reseed_counter is already known to
    // be less than or equal to SB_HMAC_DRBG_RESEED_INTERVAL .
    drbg->reseed_counter++;

#ifdef SB_TEST
    if (drbg->dangerous_nonsense_count) {
        /* output has been advanced by output_len */
        output -= output_len;
        memset(output, 0xFF, output_len);
        drbg->dangerous_nonsense_count--;
    }
#endif

    return SB_SUCCESS;
}

sb_error_t sb_hmac_drbg_generate_additional_vec
    (sb_hmac_drbg_state_t drbg[static const restrict 1],
     sb_byte_t* restrict output, size_t const output_len,
     const sb_byte_t* const additional[static const SB_HMAC_DRBG_ADD_VECTOR_LEN],
     const size_t additional_len[static const SB_HMAC_DRBG_ADD_VECTOR_LEN])
{
    return sb_hmac_drbg_generate_additional_vec_opt
        (drbg, output, output_len, additional, additional_len, 1);
}

sb_error_t sb_hmac_drbg_generate(sb_hmac_drbg_state_t
                                 drbg[static const restrict 1],
                                 sb_byte_t* const output,
                                 size_t const output_len)
{
    static const sb_byte_t* const
        additional[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { NULL };
    static const size_t additional_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { 0 };
    return sb_hmac_drbg_generate_additional_vec_opt(drbg, output, output_len,
                                                    additional, additional_len,
                                                    0);
}

static const sb_byte_t SB_HMAC_DRBG_ADDITIONAL_DUMMY[1] = { 0 };

sb_error_t sb_hmac_drbg_generate_additional_dummy(sb_hmac_drbg_state_t
                                                  drbg[static const restrict 1],
                                                  sb_byte_t* const output,
                                                  size_t const output_len)
{
    const sb_byte_t* additional[SB_HMAC_DRBG_ADD_VECTOR_LEN] =
        { SB_HMAC_DRBG_ADDITIONAL_DUMMY };
    const size_t additional_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] =
        { sizeof(SB_HMAC_DRBG_ADDITIONAL_DUMMY) };
    return sb_hmac_drbg_generate_additional_vec_opt
        (drbg, output, output_len, additional, additional_len, 1);
}

#ifdef SB_TEST

// This is one test from the CAVP sample vectors; the rest of the tests are
// exercised in a file-driven test.

static const sb_byte_t TEST_E1[] = {
    0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde, 0x1c,
    0xbd, 0xc4, 0x6e, 0x68, 0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb, 0x93, 0x5e,
    0xe2, 0x85, 0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88
};
static const sb_byte_t TEST_N1[] = {
    0x65, 0x9b, 0xa9, 0x6c, 0x60, 0x1d, 0xc6, 0x9f, 0xc9, 0x02, 0x94, 0x08,
    0x05, 0xec, 0x0c, 0xa8
};

static const sb_byte_t TEST_R1[] = {
    0xe5, 0x28, 0xe9, 0xab, 0xf2, 0xde, 0xce, 0x54, 0xd4, 0x7c, 0x7e, 0x75,
    0xe5, 0xfe, 0x30, 0x21, 0x49, 0xf8, 0x17, 0xea, 0x9f, 0xb4, 0xbe, 0xe6,
    0xf4, 0x19, 0x96, 0x97, 0xd0, 0x4d, 0x5b, 0x89, 0xd5, 0x4f, 0xbb, 0x97,
    0x8a, 0x15, 0xb5, 0xc4, 0x43, 0xc9, 0xec, 0x21, 0x03, 0x6d, 0x24, 0x60,
    0xb6, 0xf7, 0x3e, 0xba, 0xd0, 0xdc, 0x2a, 0xba, 0x6e, 0x62, 0x4a, 0xbf,
    0x07, 0x74, 0x5b, 0xc1, 0x07, 0x69, 0x4b, 0xb7, 0x54, 0x7b, 0xb0, 0x99,
    0x5f, 0x70, 0xde, 0x25, 0xd6, 0xb2, 0x9e, 0x2d, 0x30, 0x11, 0xbb, 0x19,
    0xd2, 0x76, 0x76, 0xc0, 0x71, 0x62, 0xc8, 0xb5, 0xcc, 0xde, 0x06, 0x68,
    0x96, 0x1d, 0xf8, 0x68, 0x03, 0x48, 0x2c, 0xb3, 0x7e, 0xd6, 0xd5, 0xc0,
    0xbb, 0x8d, 0x50, 0xcf, 0x1f, 0x50, 0xd4, 0x76, 0xaa, 0x04, 0x58, 0xbd,
    0xab, 0xa8, 0x06, 0xf4, 0x8b, 0xe9, 0xdc, 0xb8,
};

_Bool sb_test_hmac_drbg(void)
{
    sb_byte_t r[128];
    sb_hmac_drbg_state_t drbg;
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, TEST_E1, sizeof(TEST_E1), TEST_N1,
                          sizeof(TEST_N1), NULL, 0));
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_generate(&drbg, r, sizeof(TEST_R1)));
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_generate(&drbg, r, sizeof(TEST_R1)));
    SB_TEST_ASSERT_EQUAL(r, TEST_R1, sizeof(TEST_R1));
    return 1;
}

#endif
