/** @file sb_wycheproof_hmac_test.c
 *  @brief Test driver for wycheproof known answer HMAC tests.
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

#include "../src/sb_test.h"
#include "../src/sb_test_cavp.h"

// Erase the dest buffer and copy the contents of src into dest.
static _Bool copy_buf(sb_test_buf_t* const dest, 
                      const sb_test_buf_t* const src) 
{
    sb_test_buf_free(dest);
    dest->len = src->len >> 1u;
    dest->buf = malloc(dest->len);
    SB_TEST_ASSERT(sb_test_string_to_bytes(src, dest->buf, dest->len));
    return 1;
}

static _Bool parse_hmac_test_block(FILE* const handle, 
                                   sb_test_buf_t* const key, 
                                   sb_test_buf_t* const mess,
                                   sb_test_buf_t* const tag,
                                   _Bool* const res)
{
    sb_test_buf_free(key);
    sb_test_buf_free(mess);
    sb_test_buf_free(tag);

    sb_test_buf_t line = sb_test_buf_init;
    while(1) {
        if (!sb_test_read_line(handle, &line)) {
            sb_test_buf_free(&line);
            return 0;
        }
        // Stop at the first non-empty line
        if (line.len != 0) {
            break;
        }
    }

    // This line should contain the key 
    SB_TEST_ASSERT(copy_buf(key, &line));

    SB_TEST_ASSERT(sb_test_read_line(handle, &line));
    // This line should contain the message. This can be empty.
    if (line.len != 0) {
        SB_TEST_ASSERT(copy_buf(mess, &line));
    }

    SB_TEST_ASSERT(sb_test_read_line(handle, &line));
    // This line should contain the tag
    SB_TEST_ASSERT(copy_buf(tag, &line));

    SB_TEST_ASSERT(sb_test_read_line(handle, &line));
    // This line should contain the result
    *res = line.buf[0] == '1';

    sb_test_buf_free(&line);

    return 1;
}

static _Bool sb_test_wycheproof_hmac(const char* const filename)
{
    FILE* tests = NULL;

    sb_test_buf_t key = sb_test_buf_init;
    sb_test_buf_t msg = sb_test_buf_init;
    sb_test_buf_t tag = sb_test_buf_init;
    _Bool result = 0;
    sb_hmac_sha256_state_t hmac;
    sb_byte_t actual_out[SB_SHA256_SIZE];

    SB_TEST_ASSERT(sb_test_open(filename, &tests));

    while(parse_hmac_test_block(tests, &key, &msg, &tag, &result)) {
        sb_hmac_sha256(&hmac, actual_out, key.buf, key.len, 
                                          msg.buf, msg.len);
        if (result) {
            // The known tag and the actual output should be equal.
            SB_TEST_ASSERT_EQUAL_2(1, *tag.buf, *actual_out, tag.len);
        } else {
            // The known tag and the actual output should not be equal.
            SB_TEST_ASSERT_EQUAL_2(0, *tag.buf, *actual_out, tag.len);
        }
    }

    return 1;
}

_Bool sb_test_wycheproof_hmac_sha256(void) 
{
    return sb_test_wycheproof_hmac("wycheproof/testvectors/hmac_sha256_test");
}

#endif
