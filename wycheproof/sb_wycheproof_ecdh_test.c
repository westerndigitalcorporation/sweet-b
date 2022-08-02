/** @file sb_wycheproof_ecdh_test.c
 *  @brief Test driver for wycheproof known answer ECDH tests.
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is part of Sweet B, a safe, compact, embeddable library for
 * elliptic curve cryptography.
 *
 * https://github.com/westerndigitalcorporation/sweet-b
 *
 * Copyright (c) 2022 Western Digital Corporation or its affiliates.
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

#include <stdio.h>
#include <string.h>

#ifdef SB_TEST

#include "../src/sb_test_cavp.h"
#include "../src/sb_test.h"

static _Bool parse_ecdh_block(FILE* const handle, 
                              sb_sw_public_t* const pub, 
                              sb_sw_private_t* const priv, 
                              sb_sw_shared_secret_t* const shared)
{
    sb_test_buf_t line = sb_test_buf_init;

    // Skip over newlines
    while (1) {
        if (!sb_test_read_line(handle, &line)) {
            // Return 0 if we've reached the end of the file.
            return 0;
        }
        if (line.len != 0) {
            break;
        }
    }

    // This line should contain a public key.
    SB_TEST_BYTES(&line, *pub);

    SB_TEST_ASSERT(sb_test_read_line(handle, &line));
    // This line should contain a private key.
    SB_TEST_BYTES(&line, *priv);
    
    SB_TEST_ASSERT(sb_test_read_line(handle, &line));
    // This line should contain a shared secret.
    SB_TEST_BYTES(&line, *shared);
    sb_test_buf_free(&line);

    return 1;
}

static _Bool sb_test_wycheproof_ecdh(sb_sw_curve_id_t curve, 
                                     const char* const filename) 
{
    FILE* tests = NULL;

    sb_sw_public_t pub;
    sb_sw_private_t priv;
    sb_sw_shared_secret_t expect_shared, actual_shared;

    SB_TEST_ASSERT(sb_test_open(filename, &tests));
    while(parse_ecdh_block(tests, &pub, &priv, &expect_shared)) {
        sb_sw_context_t ct;

        SB_TEST_ASSERT_SUCCESS(
            sb_sw_valid_public_key(&ct, &pub, curve, SB_DATA_ENDIAN_BIG));
         SB_TEST_ASSERT_SUCCESS(
            sb_sw_valid_private_key(&ct, &priv, curve, SB_DATA_ENDIAN_BIG));

        SB_TEST_ASSERT_SUCCESS(
            sb_sw_shared_secret(&ct, &actual_shared, &priv, &pub, 
                                NULL, curve, SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_EQUAL(expect_shared, actual_shared);
    }

    return 1;
}

_Bool sb_test_wycheproof_ecdh_secp256k1(void) 
{
    return sb_test_wycheproof_ecdh(SB_SW_CURVE_SECP256K1, 
                                "wycheproof/testvectors/ecdh_secp256k1_test");
}

_Bool sb_test_wycheproof_ecdh_p256(void)
{
    return sb_test_wycheproof_ecdh(SB_SW_CURVE_P256, 
                                "wycheproof/testvectors/ecdh_secp256r1_test");
}

#endif
