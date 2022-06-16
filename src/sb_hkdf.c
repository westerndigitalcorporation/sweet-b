/** @file sb_hkdf.c
 *  @brief implementation of HKDF with HMAC-SHA256
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
#include "sb_time.h"
#include <sb_hkdf.h>
#include <string.h>

void sb_hkdf_extract_init(sb_hkdf_state_t hkdf[static const restrict 1],
                          const sb_byte_t* const restrict salt,
                          size_t const salt_len)
{
    memset(hkdf, 0, sizeof(sb_hkdf_state_t));

    // Indicate that this method's runtime should not depend on salt's value
    sb_poison_input(salt, salt_len);

    // if salt is not provided, it is set to a string of HashLen zeros (RFC5869)
    if (salt_len > 0) {
        sb_hmac_sha256_init(&hkdf->hmac, salt, salt_len);
    } else {
        sb_hmac_sha256_init(&hkdf->hmac, hkdf->output, SB_SHA256_SIZE);
    }
}

void sb_hkdf_extract_update(sb_hkdf_state_t hkdf[static const restrict 1],
                            const sb_byte_t* const restrict input,
                            size_t const input_len)
{
    sb_hmac_sha256_update(&hkdf->hmac, input, input_len);
}

void sb_hkdf_extract_finish(sb_hkdf_state_t hkdf[static const restrict 1])
{
    // PRK = HMAC-HASH(salt, IKM)
    sb_hmac_sha256_finish(&hkdf->hmac, hkdf->output);

    // PRK is used as the HMAC key in all subsequent expand operations
    sb_hmac_sha256_init(&hkdf->hmac, hkdf->output, SB_SHA256_SIZE);

    // Avoid keeping any particular key material in the output. In
    // particular, the hkdf object SHOULD stay the same after multiple calls
    // to expand, which requires that the output be nullified.
    memset(hkdf->output, 0, SB_SHA256_SIZE);
}

void sb_hkdf_extract(sb_hkdf_state_t hkdf[static const restrict 1],
                     const sb_byte_t* const restrict salt,
                     size_t const salt_len,
                     const sb_byte_t* const restrict input,
                     size_t const input_len)
{
    sb_hkdf_extract_init(hkdf, salt, salt_len);
    sb_hkdf_extract_update(hkdf, input, input_len);
    sb_hkdf_extract_finish(hkdf);
}

void sb_hkdf_kdf_init(sb_hkdf_state_t hkdf[static const restrict 1],
                      const sb_byte_t* const restrict input,
                      size_t const input_len)
{
    memset(hkdf, 0, sizeof(sb_hkdf_state_t));

    // Indicate that this method's runtime should not depend on input's value
    sb_poison_input(input, input_len);

    sb_hmac_sha256_init(&hkdf->hmac, input, input_len);
}

void sb_hkdf_expand(sb_hkdf_state_t hkdf[static const restrict 1],
                    const sb_byte_t* const restrict info,
                    size_t const info_len,
                    sb_byte_t* const restrict output,
                    size_t const output_len)
{
    size_t bytes_produced = 0;
    sb_byte_t iter = 1;

    // Indicate that this method's runtime should not depend on info's value
    sb_poison_input(info, info_len);

    while (bytes_produced < output_len) {
        size_t bytes = output_len - bytes_produced;
        if (bytes > SB_SHA256_SIZE) {
            bytes = SB_SHA256_SIZE;
        }

        // T(0) = empty string
        // T(n) = HMAC(PRK, T(n - 1) | info | n)

        if (bytes_produced > 0) {
            sb_hmac_sha256_update(&hkdf->hmac, hkdf->output, SB_SHA256_SIZE);
        }

        sb_hmac_sha256_update(&hkdf->hmac, info, info_len);
        sb_hmac_sha256_update(&hkdf->hmac, &iter, 1);

        sb_hmac_sha256_finish(&hkdf->hmac, hkdf->output);
        sb_hmac_sha256_reinit(&hkdf->hmac);

        memcpy(output + bytes_produced, hkdf->output, bytes);
        bytes_produced += bytes;
        iter++;
    }

    // Avoid keeping any particular key material in the output. In
    // particular, the hkdf object SHOULD stay the same after multiple calls
    // to expand, which requires that the output be nullified.
    memset(hkdf->output, 0, SB_SHA256_SIZE);
}

#ifdef SB_TEST

// These test vectors are from RFC 5869.

static const sb_byte_t TEST_IKM_1[] = {
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B
};

static const sb_byte_t TEST_SALT_1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C
};

static const sb_byte_t TEST_INFO_1[] = {
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9
};

static const sb_byte_t TEST_OKM_1[] = {
    0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A,
    0x90, 0x43, 0x4F, 0x64, 0xD0, 0x36, 0x2F, 0x2A,
    0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C,
    0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF,
    0x34, 0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18,
    0x58, 0x65
};

static const sb_byte_t TEST_IKM_2[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
};

static const sb_byte_t TEST_SALT_2[] = {
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static const sb_byte_t TEST_INFO_2[] = {
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

static const sb_byte_t TEST_OKM_2[] = {
    0xB1, 0x1E, 0x39, 0x8D, 0xC8, 0x03, 0x27, 0xA1,
    0xC8, 0xE7, 0xF7, 0x8C, 0x59, 0x6A, 0x49, 0x34,
    0x4F, 0x01, 0x2E, 0xDA, 0x2D, 0x4E, 0xFA, 0xD8,
    0xA0, 0x50, 0xCC, 0x4C, 0x19, 0xAF, 0xA9, 0x7C,
    0x59, 0x04, 0x5A, 0x99, 0xCA, 0xC7, 0x82, 0x72,
    0x71, 0xCB, 0x41, 0xC6, 0x5E, 0x59, 0x0E, 0x09,
    0xDA, 0x32, 0x75, 0x60, 0x0C, 0x2F, 0x09, 0xB8,
    0x36, 0x77, 0x93, 0xA9, 0xAC, 0xA3, 0xDB, 0x71,
    0xCC, 0x30, 0xC5, 0x81, 0x79, 0xEC, 0x3E, 0x87,
    0xC1, 0x4C, 0x01, 0xD5, 0xC1, 0xF3, 0x43, 0x4F,
    0x1D, 0x87
};

static const sb_byte_t TEST_OKM_3[] = {
    0x8D, 0xA4, 0xE7, 0x75, 0xA5, 0x63, 0xC1, 0x8F,
    0x71, 0x5F, 0x80, 0x2A, 0x06, 0x3C, 0x5A, 0x31,
    0xB8, 0xA1, 0x1F, 0x5C, 0x5E, 0xE1, 0x87, 0x9E,
    0xC3, 0x45, 0x4E, 0x5F, 0x3C, 0x73, 0x8D, 0x2D,
    0x9D, 0x20, 0x13, 0x95, 0xFA, 0xA4, 0xB6, 0x1A,
    0x96, 0xC8
};

/* This test runs each of the cases above, and also validates that
 * sb_hkdf_extract is equivalent to using HMAC-SHA256(salt, ikm) with
 * sb_hkdf_kdf_init. */
_Bool sb_test_hkdf(void)
{
    sb_hkdf_state_t hkdf, hkdf_copy;
    sb_hmac_sha256_state_t hmac;
    sb_byte_t hmac_output[SB_SHA256_SIZE];

#define SB_RUN_TEST(n) do { \
    sb_byte_t output[sizeof(TEST_OKM_ ## n)]; \
    sb_hkdf_extract(&hkdf, TEST_SALT_ ## n, sizeof(TEST_SALT_ ## n), \
                    TEST_IKM_ ## n, sizeof(TEST_IKM_ ## n)); \
    hkdf_copy = hkdf; \
    sb_hkdf_expand(&hkdf, TEST_INFO_ ## n, sizeof(TEST_INFO_ ## n), \
                   output, sizeof(output)); \
    SB_TEST_ASSERT_EQUAL(output, TEST_OKM_ ## n); \
    SB_TEST_ASSERT_EQUAL(hkdf, hkdf_copy); \
    sb_hmac_sha256_init(&hmac, TEST_SALT_ ## n, sizeof(TEST_SALT_ ## n)); \
    sb_hmac_sha256_update(&hmac, TEST_IKM_ ## n, sizeof(TEST_IKM_ ## n)); \
    sb_hmac_sha256_finish(&hmac, hmac_output); \
    sb_hkdf_kdf_init(&hkdf, hmac_output, sizeof(hmac_output)); \
    SB_TEST_ASSERT_EQUAL(hkdf, hkdf_copy); \
} while (0)

    SB_RUN_TEST(1);
    SB_RUN_TEST(2);

    // Test 3 uses Test 1's IKM with no salt or info
    {
        sb_byte_t output[sizeof(TEST_OKM_3)];
        sb_hkdf_extract_init(&hkdf, NULL, 0);
        for (size_t i = 0; i < sizeof(TEST_IKM_1); i++) {
            sb_hkdf_extract_update(&hkdf, &TEST_IKM_1[i], 1);
        }
        sb_hkdf_extract_finish(&hkdf);
        hkdf_copy = hkdf;
        sb_hkdf_expand(&hkdf, NULL, 0, output, sizeof(output));
        SB_TEST_ASSERT_EQUAL(output, TEST_OKM_3);
        SB_TEST_ASSERT_EQUAL(hkdf, hkdf_copy);
    }

    return 1;
}

#endif
