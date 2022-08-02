/** @file sb_test_cavp.c
 *  @brief Implementation of the NIST CAVP sample test vectors for Sweet B
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

#include <stdint.h>
#include <stdlib.h>

#include "sb_types.h"
#include "sb_hmac_drbg.h"
#include "sb_sw_context.h"
#include "sb_fe.h"
#include "sb_sw_lib.h"
#include "sb_sw_curves.h"
#include "sb_test_cavp.h"

#ifdef SB_TEST

#define ECDH_SHARED_SECRET_VECTORS SB_TEST_FILE("KAS_ECC_CDH_PrimitiveTest.txt")
#define SIGNATURE_VECTORS SB_TEST_FILE("SigGenComponent.txt")
#define HMAC_VECTORS SB_TEST_FILE("HMAC.rsp")

#define SHA256_SMALL_VECTORS SB_TEST_FILE("SHA256ShortMsg.rsp")
#define SHA256_LONG_VECTORS SB_TEST_FILE("SHA256LongMsg.rsp")
#define SHA256_MONTE_VECTORS SB_TEST_FILE("SHA256Monte.rsp")

#define HMAC_DBRG_VECTORS SB_TEST_FILE("HMAC_DRBG.rsp")

#define SB_TEST_FILE(in) ("./cavp/" in)

static _Bool sb_test_hex_byte_to_nibble(const sb_byte_t hex,
                                        sb_byte_t* const nibble)
{
    if (hex >= '0' && hex <= '9') {
        *nibble |= (sb_byte_t) (hex - '0');
    } else if (hex >= 'A' && hex <= 'F') {
        *nibble |= (sb_byte_t) (hex - 'A') + 0xA;
    } else if (hex >= 'a' && hex <= 'f') {
        *nibble |= (sb_byte_t) (hex - 'a') + 0xA;
    } else {
        return 0;
    }

    return 1;
}

// Convert a hex string from input to a set of bytes
_Bool sb_test_string_to_bytes(const sb_test_buf_t* const string,
                              sb_byte_t* const bytes,
                              size_t const blen)
{
    if (string->len & 1u || // must be even
        (string->len >> 1u) != blen) {
        return 0;
    }

    for (size_t i = 0; i < string->len; i += 2) {
        uint8_t value = 0;
        SB_TEST_ASSERT(sb_test_hex_byte_to_nibble(string->buf[i], &value));
        value <<= 4;
        SB_TEST_ASSERT(sb_test_hex_byte_to_nibble(string->buf[i + 1], &value));
        bytes[i >> 1u] = value;
    }
    return 1;
}

_Bool sb_test_open(const char* const name, FILE** const handle)
{
    *handle = fopen(name, "r");

    if (!*handle) {
        printf("required test vector file missing: %s\n", name);
        return 0;
    }

    return 1;
}

void sb_test_buf_free(sb_test_buf_t* const buf)
{
    sb_unpoison_output(buf->buf, buf->len);
    free(buf->buf);
    *buf = sb_test_buf_init;
}

_Bool sb_test_read_line(FILE* const handle, sb_test_buf_t* const line)
{
    sb_test_buf_free(line);

    line->len = 16;
    line->buf = malloc(line->len);
    if (!line->buf) {
        return 0;
    }

    size_t i = 0;

    while (1) {
        const int ci = fgetc(handle);
        switch (ci) {
            case EOF: {
                sb_test_buf_free(line);
                return 0;
            }
            case '\r': { // skip carriage returns
                break;
            }
            case '\n': {
                line->len = i;
                line->buf[i] = 0;
                return 1;
            }
            default: {
                line->buf[i] = (sb_byte_t) ci;
                i++;
                if (i >= line->len) {
                    line->len <<= 1;
                    line->buf = realloc(line->buf, line->len);
                    if (!line->buf) {
                        return 0;
                    }
                }
            }
        }
    }
}

_Bool sb_test_advance_to_section(FILE* const handle, const char* const section)
{
    sb_test_buf_t line = sb_test_buf_init;
    const size_t section_len = strlen(section);

    while (1) {
        SB_TEST_ASSERT(sb_test_read_line(handle, &line));
        if (line.len == section_len &&
            memcmp(line.buf, section, section_len) == 0) {
            sb_test_buf_free(&line);
            return 1;
        }
    }
}

static _Bool sb_test_valid_key_value(sb_test_buf_t* const line)
{
    for (size_t i = 0; i < line->len; i++) {
        if (line->buf[i] == '=') {
            return 1;
        }
    }
    return 0;
}

static _Bool sb_test_concat(sb_test_buf_t* const first,
                            sb_test_buf_t* const second)
{
    first->buf = realloc(first->buf, first->len + second->len);
    if (!first->buf) {
        return 1;
    }
    memcpy(first->buf + first->len, second->buf, second->len);
    first->len += second->len;
    sb_test_buf_free(second);
    return 0;
}

_Bool sb_test_fetch_next_value(FILE* const handle, sb_test_buf_t* const value)
{
    sb_unpoison_output(value->buf, value->len);
    while (1) {
        if (!sb_test_read_line(handle, value) ||
            (value->len > 0 && value->buf[0] == '[')) {
            sb_test_buf_free(value);
            return 0;
        }

        if (!sb_test_valid_key_value(value)) {
            continue;
        }

        _Bool found_value = 0;
        for (size_t i = 0; i < value->len; i++) {
            if (value->buf[i] == ' ') {
                continue;
            } else if (found_value) {
                value->len = value->len - i;
                memmove(value->buf, value->buf + i,
                        value->len + 1); // preserve nul-termination
                return 1;
            } else if (value->buf[i] == '=') {
                found_value = 1;
                continue;
            }
        }

        sb_test_buf_free(value);
        return 0;
    }
}

_Bool sb_test_fetch_next_int(FILE* const handle, size_t* const value)
{
    sb_test_buf_t buf = sb_test_buf_init;

    if (sb_test_fetch_next_value(handle, &buf)) {
        *value = strtoul((const char*) buf.buf, NULL, 10);
        sb_test_buf_free(&buf);
        return 1;
    }

    sb_test_buf_free(&buf);
    return 0;
}

// Actual tests start here

static _Bool
sb_test_cavp_ecdh_shared_secret(sb_sw_curve_id_t curve, const char* name)
{
    FILE* tests = NULL;
    size_t count = 0, i = 0;

    sb_test_buf_t x = sb_test_buf_init, y = sb_test_buf_init;

    sb_sw_private_t prv_key_a;
    sb_sw_public_t pub_key_a, pub_key_b;
    sb_sw_shared_secret_t secret;

    SB_TEST_ASSERT(sb_test_open(ECDH_SHARED_SECRET_VECTORS, &tests));
    SB_TEST_ASSERT(sb_test_advance_to_section(tests, name));

    while (sb_test_fetch_next_int(tests, &count)) {
        SB_TEST_ASSERT(count == i);
        i++;

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &y));
        sb_test_concat(&x, &y);
        SB_TEST_BYTES(&x, pub_key_b);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_BYTES(&x, prv_key_a);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &y));
        sb_test_concat(&x, &y);
        SB_TEST_BYTES(&x, pub_key_a);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_BYTES(&x, secret);

        sb_sw_shared_secret_t out;
        sb_sw_context_t ct;
        sb_sw_public_t pub_key_a_out;
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_compute_public_key(&ct, &pub_key_a_out, &prv_key_a, NULL,
                                     curve, SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_EQUAL(pub_key_a, pub_key_a_out);
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_shared_secret(&ct, &out, &prv_key_a, &pub_key_b, NULL,
                                curve, SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_EQUAL(secret, out);

        sb_unpoison_output(x.buf, x.len);
        sb_unpoison_output(y.buf, y.len);
    }

    sb_test_buf_free(&x);
    sb_test_buf_free(&y);
    fclose(tests);

    return 1;
}

static _Bool sb_test_cavp_signatures(sb_sw_curve_id_t curve, const char* name)
{
    FILE* tests = NULL;
    size_t count = 0;

    sb_test_buf_t message = sb_test_buf_init;

    sb_test_buf_t x = sb_test_buf_init, y = sb_test_buf_init;

    sb_sw_message_digest_t digest;
    sb_sw_private_t prv_key_a;
    sb_sw_public_t pub_key_a;
    sb_sw_signature_t signature;
    sb_single_t message_secret;

    SB_TEST_ASSERT(sb_test_open(SIGNATURE_VECTORS, &tests));
    SB_TEST_ASSERT(sb_test_advance_to_section(tests, name));

    while (sb_test_fetch_next_value(tests, &message)) {
        count++;

        SB_TEST_BYTES_RAW(&message);
        memset(digest.bytes, 0, sizeof(digest));
        memcpy(digest.bytes + ((message.len < sizeof(digest)) ?
                               (sizeof(digest) - message.len) : 0),
               message.buf,
               ((message.len > sizeof(digest)) ? sizeof(digest) : message.len));

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_BYTES(&x, prv_key_a);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &y));
        sb_test_concat(&x, &y);
        SB_TEST_BYTES(&x, pub_key_a);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_BYTES(&x, message_secret);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &x));
        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &y));
        sb_test_concat(&x, &y);
        SB_TEST_BYTES(&x, signature);

        sb_sw_context_t ct;
        sb_sw_public_t pub_key_a_out;
        sb_sw_signature_t signature_out;

        SB_TEST_ASSERT_SUCCESS(
            sb_sw_compute_public_key(&ct, &pub_key_a_out, &prv_key_a, NULL,
                                     curve, SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_EQUAL(pub_key_a, pub_key_a_out);

        SB_TEST_ASSERT_SUCCESS(
            sb_sw_valid_public_key(&ct, &pub_key_a, curve, SB_DATA_ENDIAN_BIG));

        SB_TEST_ASSERT_SUCCESS(
            sb_sw_sign_message_digest_with_k_beware_of_the_leopard
                (&ct, &signature_out, &prv_key_a, &digest, &message_secret,
                 curve, SB_DATA_ENDIAN_BIG));

        SB_TEST_ASSERT_EQUAL(signature, signature_out);

        SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature(&ct,
                                                      &signature,
                                                      &pub_key_a,
                                                      &digest,
                                                      NULL,
                                                      curve,
                                                      SB_DATA_ENDIAN_BIG));

    }

    sb_test_buf_free(&message);
    sb_test_buf_free(&x);
    sb_test_buf_free(&y);
    fclose(tests);

    return 1;
}

static _Bool sb_test_cavp_hmac(const char* name)
{
    FILE* tests = NULL;
    size_t count = 0, klen, tlen, i = 0;

    sb_test_buf_t key = sb_test_buf_init;
    sb_test_buf_t message = sb_test_buf_init;
    sb_test_buf_t mac = sb_test_buf_init;

    SB_TEST_ASSERT(sb_test_open(HMAC_VECTORS, &tests));
    SB_TEST_ASSERT(sb_test_advance_to_section(tests, name));

    while (sb_test_fetch_next_int(tests, &count)) {
        SB_TEST_ASSERT(count == i);
        i++;

        SB_TEST_ASSERT(sb_test_fetch_next_int(tests, &klen));
        SB_TEST_ASSERT(sb_test_fetch_next_int(tests, &tlen));

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &key));
        SB_TEST_BYTES_RAW(&key);
        SB_TEST_ASSERT(klen == key.len);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &message));
        SB_TEST_BYTES_RAW(&message);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &mac));
        SB_TEST_BYTES_RAW(&mac);

        sb_hmac_sha256_state_t hmac;
        sb_byte_t h[SB_SHA256_SIZE];

        sb_hmac_sha256_init(&hmac, key.buf, key.len);
        sb_hmac_sha256_update(&hmac, message.buf, message.len);
        sb_hmac_sha256_finish(&hmac, h);

        SB_TEST_ASSERT_EQUAL(h, mac.buf[0], tlen);
        
        // Unpoison these fields so they can go through the file I/O before
        // getting repoisoned.
        sb_unpoison_output(key.buf, key.len);
        sb_unpoison_output(message.buf, message.len);
        sb_unpoison_output(mac.buf, mac.len);
    }

    sb_test_buf_free(&key);
    sb_test_buf_free(&message);
    sb_test_buf_free(&mac);
    fclose(tests);
    return 1;
}

extern _Bool sb_test_sha256_cavp_file(const char* file);
extern _Bool sb_test_sha256_cavp_file_monte(const char* file);

static _Bool
sb_test_cavp_hmac_drbg(const char* file, const char* name, size_t section)
{
    FILE* tests = NULL;
    size_t count, i;

    sb_test_buf_t entropy = sb_test_buf_init;
    sb_test_buf_t nonce = sb_test_buf_init;
    sb_test_buf_t personalization = sb_test_buf_init;
    sb_test_buf_t extra_1 = sb_test_buf_init;
    sb_test_buf_t extra_2 = sb_test_buf_init;
    sb_test_buf_t output = sb_test_buf_init;

    SB_TEST_ASSERT(sb_test_open(file, &tests));

    for (i = 0; i < section; i++) {
        SB_TEST_ASSERT(sb_test_advance_to_section(tests, name));
    }

    // Ditch the rest of the preamble
    for (i = 0; i < 6; i++) {
        SB_TEST_ASSERT(sb_test_read_line(tests, &extra_1));
    }

    i = 0;

    while (sb_test_fetch_next_int(tests, &count)) {
        SB_TEST_ASSERT(count == i);
        i++;

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &entropy));
        SB_TEST_BYTES_RAW(&entropy);

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &nonce));
        SB_TEST_BYTES_RAW(&nonce);

        if (sb_test_fetch_next_value(tests, &personalization)) {
            SB_TEST_BYTES_RAW(&personalization);
        }

        if (sb_test_fetch_next_value(tests, &extra_1)) {
            SB_TEST_BYTES_RAW(&extra_1);
        }

        if (sb_test_fetch_next_value(tests, &extra_2)) {
            SB_TEST_BYTES_RAW(&extra_2);
        }

        SB_TEST_ASSERT(sb_test_fetch_next_value(tests, &output));
        SB_TEST_BYTES_RAW(&output);

        sb_hmac_drbg_state_t drbg;
        sb_byte_t* output_act = malloc(output.len);

        SB_TEST_ASSERT(output_act != NULL);

        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_init(&drbg, entropy.buf, entropy.len,
                              nonce.buf, nonce.len,
                              personalization.buf, personalization.len));

        const sb_byte_t* add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { NULL };
        size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = { 0 };

        if (extra_1.len) {
            add[0] = extra_1.buf;
            add_len[0] = extra_1.len;
            SB_TEST_ASSERT_SUCCESS(
                sb_hmac_drbg_generate_additional_vec(&drbg, output_act,
                                                     output.len, add, add_len));
        } else {
            SB_TEST_ASSERT_SUCCESS(
                sb_hmac_drbg_generate(&drbg, output_act, output.len));
        }

        if (extra_2.len) {
            add[0] = extra_2.buf;
            add_len[0] = extra_2.len;
            SB_TEST_ASSERT_SUCCESS(
                sb_hmac_drbg_generate_additional_vec(&drbg, output_act,
                                                     output.len, add, add_len));
        } else {
            sb_hmac_drbg_generate(&drbg, output_act, output.len);
        }

        SB_TEST_ASSERT_EQUAL(output_act[0], output.buf[0], output.len);

        sb_unpoison_output(output_act, output.len);
        free(output_act);
    }

    sb_test_buf_free(&entropy);
    sb_test_buf_free(&nonce);
    sb_test_buf_free(&personalization);
    sb_test_buf_free(&extra_1);
    sb_test_buf_free(&extra_2);
    sb_test_buf_free(&output);

    fclose(tests);
    return 1;
}

_Bool sb_test_cavp_hmac_drbg_sha256(void)
{
    _Bool result = 1;
    size_t i;

    // The NIST tests contain 16 test groups for SHA-256
    for (i = 0; i < 16; i++) {
        result &= sb_test_cavp_hmac_drbg(HMAC_DBRG_VECTORS, "[SHA-256]", i);
    }
    
    return result;
}

_Bool sb_test_cavp_sha256_monte(void)
{
    return sb_test_sha256_cavp_file_monte(SHA256_MONTE_VECTORS);
}

_Bool sb_test_cavp_sha256_small(void)
{
    return sb_test_sha256_cavp_file(SHA256_SMALL_VECTORS);
}

_Bool sb_test_cavp_sha256_long(void)
{
    return sb_test_sha256_cavp_file(SHA256_LONG_VECTORS);
}

_Bool sb_test_cavp_hmac_sha256(void)
{
    return sb_test_cavp_hmac("[L=32]");
}

_Bool sb_test_cavp_signatures_p256_sha1(void)
{
    return sb_test_cavp_signatures(SB_SW_CURVE_P256, "[P-256,SHA-1]");
}

_Bool sb_test_cavp_signatures_p256_sha224(void)
{
    return sb_test_cavp_signatures(SB_SW_CURVE_P256, "[P-256,SHA-224]");
}

_Bool sb_test_cavp_signatures_p256_sha256(void)
{
    return sb_test_cavp_signatures(SB_SW_CURVE_P256, "[P-256,SHA-256]");
}

_Bool sb_test_cavp_signatures_p256_sha384(void)
{
    return sb_test_cavp_signatures(SB_SW_CURVE_P256, "[P-256,SHA-384]");
}

_Bool sb_test_cavp_signatures_p256_sha512(void)
{
    return sb_test_cavp_signatures(SB_SW_CURVE_P256, "[P-256,SHA-512]");
}

_Bool sb_test_cavp_ecdh_shared_secret_p256(void)
{
    return sb_test_cavp_ecdh_shared_secret(SB_SW_CURVE_P256, "[P-256]");
}

#endif
