/** @file sb_sha256.h
 *  @brief public API for SHA-256
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

#ifndef SB_SHA256_H
#define SB_SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <sb_types.h>

/** @private
  * @typedef sb_sha256_word_t
  * @brief Word size that SHA256 operates on */
typedef uint32_t sb_sha256_word_t;

/** @brief The number of bytes in a SHA256 hash. */
#define SB_SHA256_SIZE 32

/* The following two definitions are for internal use only. */

/** @private
  * @brief Size of the SHA256 block, in bytes. */
#define SB_SHA256_BLOCK_SIZE 64

/** @private
 *  @brief Intermediate hash state
 */
typedef struct sb_sha256_ihash_t {
    sb_sha256_word_t v[8]; ///< Words of the intermediate hash state
} sb_sha256_ihash_t; /**< Convenience typedef */

/** @struct sb_sha256_state_t
 *  @brief Opaque state structure. You are responsible for allocating this
 *  and passing it in to SHA256 operations. */
typedef struct sb_sha256_state_t {
    /** @privatesection */
    sb_sha256_ihash_t ihash; ///< Intermediate hash state
    sb_sha256_ihash_t a_h; ///< a through h, the working variables
    sb_sha256_word_t W[16]; ///< message schedule rotating window
    sb_byte_t buffer[SB_SHA256_BLOCK_SIZE]; ///< Block-sized buffer of input
    sb_size_t total_bytes; ///< Total number of bytes processed
} sb_sha256_state_t; /**< Convenience typedef */

/**
 * Initialize a SHA256 state object. Must be called before ::sb_sha256_update
 * is called on input bytes.
 *
 * @param [out] sha SHA256 state. Must be allocated by the caller.
 * @memberof sb_sha256_state_t
 */
extern void sb_sha256_init(sb_sha256_state_t sha[static 1]);

/**
 * Update the SHA256 state with the given input bytes. Can be used to hash a
 * large number of bytes, even when not all bytes are available in a single
 * input buffer.
 *
 * @param [in,out] sha SHA256 state. Must be allocated by the caller and have
 * been previously initialized via ::sb_sha256_init.
 * @param [in] input Input bytes of length \p len. Must not alias the SHA256
 * state. May be NULL if \p len is zero.
 * @param [in] len Length of \p input bytes.
 * @memberof sb_sha256_state_t
 */
extern void sb_sha256_update(sb_sha256_state_t sha[static restrict 1],
                             const sb_byte_t* restrict input,
                             size_t len);

/**
 * Calculate the SHA256 hash of the bytes that have been previously provided
 * in calls to ::sb_sha256_update. Invalidates the SHA256 state.
 *
 * @param [in,out] sha SHA256 state. Must be allocated by the caller and have
 * been previously initialized via ::sb_sha256_init. May have been updated by
 * one or more calls to ::sb_sha256_update.
 * @param [out] output Resulting SHA256 hash, in the form of
 * ::SB_SHA256_SIZE bytes.
 * @memberof sb_sha256_state_t
 */
extern void sb_sha256_finish(sb_sha256_state_t sha[static restrict 1],
                             sb_byte_t output[static restrict SB_SHA256_SIZE]);

/**
 * Compute the SHA256 hash of a complete input message as bytes. Requires a
 * state object allocated by the caller.
 *
 * @param [out] sha SHA256 state. Must be allocated by the caller.
 * @param [in] input Input bytes of length \p len. Must not alias the SHA256
 * state. May be NULL if \p len is zero.
 * @param [in] len Length of \p input bytes.
 * @param [out] output Resulting SHA256 hash, in the form of
 * ::SB_SHA256_SIZE bytes.
 * @memberof sb_sha256_state_t
 */
extern void sb_sha256_message(sb_sha256_state_t sha[static restrict 1],
                              sb_byte_t output[static restrict SB_SHA256_SIZE],
                              const sb_byte_t* restrict input,
                              size_t len);

#endif
