/** @file sb_hkdf.h
 *  @brief public API for HKDF with HMAC-SHA256
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

#ifndef SB_HKDF_H
#define SB_HKDF_H

#include <sb_types.h>
#include <sb_hmac_sha256.h>

/** @struct sb_hkdf_state_t
 *  @brief Opaque state structure. You are responsible for allocating this
 *  and passing it in to HKDF operations. */
typedef struct sb_hkdf_state_t {
    /** @privatesection */
    sb_hmac_sha256_state_t hmac; ///< HMAC state
    sb_byte_t output[SB_SHA256_SIZE]; ///< Intermediate HMAC output buffer
} sb_hkdf_state_t; /**< Convenience typedef */

/**
 * Extract a pseudo-random key from the given \p salt and \p input key material.
 *
 * @param [out] hkdf HKDF state. Must be allocated by the caller.
 * @param [in]  salt HKDF salt. Must not alias \p hkdf or \p input. May be NULL
 * iff \p salt_len is zero.
 * @param [in]  salt_len HKDF salt length, in bytes.
 * @param [in]  input HKDF input key material. Must not alias \p hkdf or
 * \p salt.
 * @param [in]  input_len HKDF input key material length, in bytes.
 * @memberof sb_hkdf_state_t
 */
extern void sb_hkdf_extract(sb_hkdf_state_t hkdf[static restrict 1],
                            const sb_byte_t* restrict salt,
                            size_t salt_len,
                            const sb_byte_t* restrict input,
                            size_t input_len);

/**
 * Begin extracting a pseudo-random key using the given \p salt. Must be
 * followed by calls to ::sb_hkdf_extract_update and ::sb_hkdf_extract_finish.
 *
 * @param [out] hkdf HKDF state. Must be allocated by the caller.
 * @param [in]  salt HKDF salt. Must not alias \p hkdf. May be NULL iff
 * \p salt_len is zero.
 * @param [in]  salt_len HKDF salt length, in bytes.
 * @memberof sb_hkdf_state_t
 */
extern void sb_hkdf_extract_init(sb_hkdf_state_t hkdf[static restrict 1],
                                 const sb_byte_t* restrict salt,
                                 size_t salt_len);

/**
 * Supply input to the HKDF extraction process begun by a previous call to
 * ::sb_hkdf_extract_init. Must be followed by further calls to
 * ::sb_hkdf_extract_update and a final call to ::sb_hkdf_extract_finish.
 *
 * @param [in,out] hkdf HKDF state. Must be allocated by the caller.
 * @param [in]  input HKDF input key material. Must not alias \p hkdf.
 * @param [in]  input_len HKDF input key material length, in bytes.
 * @memberof sb_hkdf_state_t
 */
extern void sb_hkdf_extract_update(sb_hkdf_state_t hkdf[static restrict 1],
                                   const sb_byte_t* restrict input,
                                   size_t input_len);

/**
 * Finish the HKDF extraction process begun by a previous call to
 * ::sb_hkdf_extract_init. Must only be followed by calls to
 * ::sb_hkdf_expand, or a call to ::sb_hkdf_extract or
 * ::sb_hkdf_extract_init to reset the HKDF state.
 *
 * @param [in,out] hkdf HKDF state. Must be allocated by the caller.
 * @memberof sb_hkdf_state_t
 */
extern void sb_hkdf_extract_finish(sb_hkdf_state_t hkdf[static restrict 1]);

/**
 * Initialize a HKDF state object using a supplied input key, in order to use
 * the expand function as a SP800-108 KBKDF operating in feedback mode.
 *
 * @param [out] hkdf HKDF state. Must be allocated by the caller.
 * @param [in]  input KDF input key material. Must not alias \p hkdf.
 * @param [in]  input_len KDF input key material length, in bytes.
 * @memberof sb_hkdf_state_t
 */
extern void sb_hkdf_kdf_init(sb_hkdf_state_t hkdf[static restrict 1],
                             const sb_byte_t* restrict input,
                             size_t input_len);

/**
 * Expand key material from a pseudo-random key. It is permitted to call this
 * function several times with the same extracted key material (for instance,
 * when using different info strings to generate keys for different purposes).
 *
 * @param [in,out] hkdf HKDF state. Must be allocated by caller and have been
 * previously initialized via ::sb_hkdf_extract.
 * @param [in]     info Optional context-specific information. May be NULL
 * iff \p info_len is zero. Must not alias \p hkdf or \p output.
 * @param [in]     info_len Length of optional context-specific information,
 * in bytes.
 * @param [out]    output HKDF output key material. Must not alias \p hkdf or
 * \p info.
 * @param [in]     output_len HKDF output key material length, in bytes.
 * @memberof sb_hkdf_state_t
 */
extern void sb_hkdf_expand(sb_hkdf_state_t hkdf[static restrict 1],
                           const sb_byte_t* restrict info,
                           size_t info_len,
                           sb_byte_t* restrict output,
                           size_t output_len);

#endif
