/** @file sb_wycheproof_ecdsa_test.c
 *  @brief Test driver for wycheproof known answer ECDSA tests.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef SB_TEST

#include "../src/sb_test_cavp.h"
#include "../src/sb_test.h"
#include "../src/sb_sw_curves.h"
#include "sb_sw_lib.h"

static const sb_byte_t NULL_ENTROPY[32] = { 0 };

// Initialize a DRBG used for semi-randomized testing. Also sets the
// additional_input_required flag so that all curve operations can be checked
// for whether they provide additional input to the DRBG to ensure
// backtracking resistance.

#define NULL_DRBG_INIT(drbg) \
    do { \
        SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_init((drbg), NULL_ENTROPY, 32, \
            NULL_ENTROPY, 32, NULL, 0)); \
        (drbg)->additional_input_required = 1; \
    } while (0)

static _Bool parse_ecdsa_key_block(FILE* const handle, 
                                   sb_sw_public_t* const pub)
{
    sb_test_buf_t line = sb_test_buf_init;
    
    while(1) {
        if (!sb_test_read_line(handle, &line)) {
            return 0;
        }
        // Skip over newlines
        if (line.len != 0) {
            break;
        }
    }

    // This line should contain the public key that we will use to verify 
    // upcoming message and signature test cases.
    SB_TEST_BYTES(&line, *pub);
    sb_test_buf_free(&line);

    return 1;
}


static _Bool parse_ecdsa_test_block(FILE* const handle,
                                    sb_sw_signature_t* const sig, 
                                    sb_test_buf_t* mess, 
                                    _Bool* const result)
{
    sb_test_buf_t line = sb_test_buf_init;
     
    while (1) {
        if (!sb_test_read_line(handle, &line)) {
            sb_test_buf_free(&line);
            return 0;
        }

        if (line.len == 2 && line.buf[0] == '=') {
            // We've reached the end of the test block. 
            sb_test_buf_free(&line);
            return 0;
        }
        // Skip over newlines
        if (line.len != 0) {
            break;
        }
    }

    // This line should contain the message to verify against
    sb_test_buf_free(mess);
    mess->len = line.len >> 1u;
    mess->buf = malloc(mess->len);
    sb_test_string_to_bytes(&line, mess->buf, mess->len);

    SB_TEST_ASSERT(sb_test_read_line(handle, &line));
    // This line should contain the signature to verify
    SB_TEST_BYTES(&line, *sig);

    SB_TEST_ASSERT(sb_test_read_line(handle, &line));
    // This line should contain a 1 if the test is valid or 0 if invalid
    *result = line.buf[0] == '1';
    
    sb_test_buf_free(&line);
    return 1;
}


static _Bool sb_test_wycheproof_ecdsa(sb_sw_curve_id_t curve, 
                                      const char* const filename)
{
    FILE* tests = NULL;
    sb_data_endian_t e = SB_DATA_ENDIAN_BIG;

    sb_sw_context_t ct;
    sb_sw_public_t pub;
    sb_test_buf_t message = sb_test_buf_init;
    sb_sw_message_digest_t digest;
    sb_sw_signature_t sig;
    _Bool result = 0;
    sb_hmac_drbg_state_t drbg;

    NULL_DRBG_INIT(&drbg);

    SB_TEST_ASSERT(sb_test_open(filename, &tests));
    while (1) {
        if (!parse_ecdsa_key_block(tests, &pub)) {
            break;
        }
        while (parse_ecdsa_test_block(tests, &sig, &message, &result)) {
            // Run the test and keep track of the result
            sb_error_t err = SB_SUCCESS;

            err |= sb_sw_valid_public_key(&ct, &pub, curve, e);

            err |= sb_sw_verify_signature_sha256(&ct, &digest, &sig, &pub, 
                                                 message.buf, message.len, 
                                                 &drbg, curve, e);

            if (result) {
                SB_TEST_ASSERT(err == SB_SUCCESS);
            } else {
                SB_TEST_ASSERT(err != SB_SUCCESS);
            }

            SB_TEST_ASSERT_SUCCESS(
                sb_hmac_drbg_reseed(&drbg, sig.bytes, 
                                    SB_ELEM_BYTES * 2, NULL, 0));
        }
    }
    sb_test_buf_free(&message);

    return 1;
}

_Bool sb_test_wycheproof_ecdsa_secp256k1(void) 
{
    return sb_test_wycheproof_ecdsa(SB_SW_CURVE_SECP256K1, 
                        "wycheproof/testvectors/ecdsa_secp256k1_sha256_test");
}

_Bool sb_test_wycheproof_ecdsa_p256(void) 
{
    return sb_test_wycheproof_ecdsa(SB_SW_CURVE_P256, 
                        "wycheproof/testvectors/ecdsa_secp256r1_sha256_test");
}

#endif 
