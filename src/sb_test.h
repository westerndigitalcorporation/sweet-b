/** @file sb_test.h
 *  @brief private API for Sweet B unit tests and debug assertions
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

#ifndef SB_TEST_H
#define SB_TEST_H

#if defined(SB_DEBUG_ASSERTS)

// Debug asserts can only be used when running unit tests as they may
// otherwise violate constant-time behavior.
#ifndef SB_TEST
#error "SB_DEBUG_ASSERTS is invalid outside of unit tests"
#endif

#include <assert.h>
#define SB_ASSERT(e, s) do { \
    assert((e) && (s)[0]); \
} while (0) 
#else
#define SB_ASSERT(e, s) do { } while (0)
#endif

#ifdef SB_TEST
#include <stdio.h>
#include <string.h>
#include "sb_types.h"
#include "sb_time.h"

#ifndef SB_TEST_ITER_DEFAULT
#define SB_TEST_ITER_DEFAULT 8192
#endif

#define SB_TEST_STRINGIFY_E(e) #e
#define SB_TEST_STRINGIFY(e) SB_TEST_STRINGIFY_E(e)

typedef struct sb_test_buf_t {
    sb_byte_t* buf;
    size_t len;
} sb_test_buf_t;

static const sb_test_buf_t sb_test_buf_init = { .buf = NULL, .len = 0 };

extern _Bool sb_test_open(const char* name, FILE** handle);
extern _Bool sb_test_read_line(FILE* handle, sb_test_buf_t* line);
extern _Bool sb_test_advance_to_section(FILE* handle, const char* section);
extern _Bool sb_test_fetch_next_int(FILE* handle, size_t* value);
extern _Bool sb_test_fetch_next_value(FILE* handle, sb_test_buf_t* value);
extern _Bool sb_test_string_to_bytes(const sb_test_buf_t* string,
                                     sb_byte_t* bytes,
                                     size_t blen);
extern void sb_test_buf_free(sb_test_buf_t* buf);

#define SB_TEST_BYTES(in, out) \
    SB_TEST_ASSERT(sb_test_string_to_bytes((in), (out).bytes, sizeof(out)))

#define SB_TEST_BYTES_RAW(in) do { \
    SB_TEST_ASSERT(sb_test_string_to_bytes((in), (in)->buf, (in)->len >> 1u)); \
    (in)->len >>= 1; \
} while (0)

extern _Bool sb_test_assert_failed(const char* file, const char* line,
                                   const char* expression);

/* For timing tests, to be used in test case situations where we know the input
 * is poison and it's still OK to use in a conditional expression */
#if SB_TIME
#define SB_TEST_IF_POISON(v) \
    for (_Bool tmp_ ## __LINE__ = (v); \
         sb_unpoison_output(&tmp_ ## __LINE__, sizeof(sb_word_t)), tmp_ ## __LINE__; \
         tmp_ ## __LINE__ = 0)
#else
#define SB_TEST_IF_POISON(v) if ((v))
#endif

#define SB_TEST_ASSERT(e) do { \
    SB_TEST_IF_POISON(!(e)) { \
        return sb_test_assert_failed(__FILE__, SB_TEST_STRINGIFY(__LINE__), #e); \
    } \
} while (0)

#define SB_TEST_ASSERT_SUCCESS(e) SB_TEST_ASSERT((e) == SB_SUCCESS)
#define SB_TEST_ASSERT_ERROR(e, ...) SB_TEST_ASSERT((e) == \
    SB_ERRORS(__VA_ARGS__))

static inline uint8_t sb_test_ctc(const void* a_v,
                                  const void* b_v,
                                  size_t len)
{
    const uint8_t* const a = (const uint8_t*) a_v;
    const uint8_t* const b = (const uint8_t*) b_v;

    uint8_t r = 0;
    
    for (size_t i = 0; i < len; i++) {
        r |= (a[i] ^ b[i]);
    }

    return ((r | (uint8_t) -r) >> 7) ^ 1;
}

#define SB_TEST_ASSERT_EQUAL_2(v, e1, e2, s) \
    do { \
        SB_TEST_ASSERT((sb_test_ctc(&(e1), &(e2), (s))) == (v)); \
    } while (0)

#define SB_TEST_ASSERT_EQUAL_1(v, e1, e2, unused) \
    SB_TEST_ASSERT_EQUAL_2(v, e1, e2, sizeof(e2))

#define SB_TEST_ASSERT_EQUAL_n(v, e1, e2, e3, a, ...) \
    a(v, e1, e2, e3)

#define SB_TEST_ASSERT_EQUAL(...) \
    SB_TEST_ASSERT_EQUAL_n(1, __VA_ARGS__, SB_TEST_ASSERT_EQUAL_2, \
        SB_TEST_ASSERT_EQUAL_1, NOT_ENOUGH_ARGUMENTS)

#define SB_TEST_ASSERT_NOT_EQUAL(...) \
    SB_TEST_ASSERT_EQUAL_n(0, __VA_ARGS__, SB_TEST_ASSERT_EQUAL_2, \
        SB_TEST_ASSERT_EQUAL_1, NOT_ENOUGH_ARGUMENTS)

#define SB_TEST_IMPL

#define SB_DEFINE_TEST(name) \
    extern _Bool sb_test_ ## name(void)

#include "sb_test_list.h"

#undef SB_TEST_IMPL
#undef SB_DEFINE_TEST

#endif

#endif
