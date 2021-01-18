/** @file sb_hmac_sha256.h
 *  @brief public API for HMAC-SHA-256
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

#ifndef SB_HMAC_SHA256_H
#define SB_HMAC_SHA256_H

#include <sb_sha256.h>

/** @struct sb_hmac_sha256_state_t
 *  @brief Opaque state structure. You are responsible for allocating this
 *  and passing it in to HMAC-SHA256 operations. */
typedef struct sb_hmac_sha256_state_t {
    /** @privatesection */
    sb_sha256_state_t sha; ///< Internal hash state
    sb_byte_t key[SB_SHA256_BLOCK_SIZE]; ///< HMAC key
} sb_hmac_sha256_state_t; /**< Convenience typedef */

/**
 * Initialize a HMAC-SHA256 state object. Must be called before
 * ::sb_hmac_sha256_update is called on input bytes.
 *
 * @param [out] hmac HMAC-SHA256 state. Must be allocated by the caller.
 * @param [in]  key HMAC-SHA256 key. Must not alias \p hmac.
 * @param [in]  keylen HMAC-SHA256 key length, in bytes.
 * @memberof sb_hmac_sha256_state_t
 */
extern void sb_hmac_sha256_init(sb_hmac_sha256_state_t hmac[static restrict 1],
                                const sb_byte_t* restrict key,
                                size_t keylen);

/**
 * Reinitialize a HMAC-SHA256 state object while preserving the original
 * input key.
 *
 * @param [in,out] hmac HMAC-SHA256 state. Must be allocated by the caller.
 * Must previously have been initialized with ::sb_hmac_sha256_init.
 * @memberof sb_hmac_sha256_state_t
 */
extern void sb_hmac_sha256_reinit(sb_hmac_sha256_state_t hmac[static 1]);

/**
 * Update the HMAC-SHA256 state with the given input bytes. Can be used to
 * calculate the HMAC of a large number of bytes, even when not all bytes
 * are available in a single input buffer.
 *
 * @param [in,out] hmac HMAC-SHA256 state. Must be allocated by the caller and
 * have been previously initialized via ::sb_hmac_sha256_init.
 * @param [in] input Input bytes of length \p len. Must not alias the HMAC
 * state. May be NULL if \p len is zero.
 * @param [in] len Length of \p input bytes.
 * @memberof sb_hmac_sha256_state_t
 */
extern void
sb_hmac_sha256_update(sb_hmac_sha256_state_t hmac[static restrict 1],
                      const sb_byte_t* restrict input,
                      size_t len);

/**
 * Calculate the HMAC-SHA256 of the bytes that have been previously provided
 * in calls to ::sb_hmac_sha256_update, using the key provided in the
 * original call to ::sb_hmac_sha256_init. The state may be reused only
 * after calling ::sb_hmac_sha256_init or ::sb_hmac_sha256_reinit to
 * initialize or reinitialize the state.
 *
 * @param [in,out] hmac HMAC-SHA256 state. Must be allocated by the caller and
 * have been previously initialized via ::sb_hmac_sha256_init. May have been
 * updated by one or more calls to ::sb_hmac_sha256_update.
 * @param [out] output Resulting HMAC-SHA256 value, in the form of
 * ::SB_SHA256_SIZE bytes.
 * @memberof sb_hmac_sha256_state_t
 */
extern void
sb_hmac_sha256_finish(sb_hmac_sha256_state_t hmac[static restrict 1],
                      sb_byte_t output[static restrict SB_SHA256_SIZE]);

/**
 * Compute the HMAC-SHA256 of the supplied input using the supplied key.
 *
 * @param [out] hmac HMAC-SHA256 state. Must be allocated by the caller.
 * @param [out] output Resulting HMAC-SHA256 value, in the form of
 * ::SB_SHA256_SIZE bytes.
 * @param [in]  key HMAC-SHA256 key. Must not alias \p hmac.
 * @param [in]  keylen HMAC-SHA256 key length, in bytes.
 * @param [in] input Input bytes of length \p len. Must not alias the HMAC
 * state. May be NULL if \p len is zero.
 * @param [in] input_len Length of \p input bytes.
 * @memberof sb_hmac_sha256_state_t
 */
extern void sb_hmac_sha256(sb_hmac_sha256_state_t hmac[static restrict 1],
                           sb_byte_t output[static restrict SB_SHA256_SIZE],
                           const sb_byte_t* restrict key,
                           size_t keylen,
                           const sb_byte_t* restrict input,
                           size_t input_len);

#endif
