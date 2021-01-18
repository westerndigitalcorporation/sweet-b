/** @file sb_hmac_drbg.h
 *  @brief public API for HMAC-DRBG using SHA-256
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

// This implementation of HMAC-DRBG based on SHA256 is provided for use in
// RFC6979-based deterministic signing. It's also appropriate for general use
// as a DRBG, so if you have access to a raw source of entropy such as an
// on-chip RNG, you should consider using this for key generation.

#ifndef SB_HMAC_DRBG_H
#define SB_HMAC_DRBG_H

#include <sb_types.h>
#include <sb_hmac_sha256.h>

/** Per SP 800-57 Part 1 Rev. 4, 5.6.1: HMAC-SHA-256 has security strength
 *  >= 256. This constant is in bytes, not bits. */
#define SB_HMAC_DRBG_SECURITY_STRENGTH 32

// Use these in your application when providing entropy

/** The minimum entropy input length for a SHA256-based HMAC-DRBG, per NIST
 *  SP 800-90A Rev. 1. */
#define SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH SB_HMAC_DRBG_SECURITY_STRENGTH

/** The minimum nonce length for a SHA256-based HMAC-DRBG, per NIST SP
 *  800-90A Rev. 1. */
#define SB_HMAC_DRBG_MIN_NONCE_LENGTH (SB_HMAC_DRBG_SECURITY_STRENGTH / 2)

#if defined(SB_HMAC_DRBG_RESEED_INTERVAL)

#if SB_HMAC_DRBG_RESEED_INTERVAL > 0x1000000000000
#error "SB_HMAC_DRBG_RESEED_INTERVAL too large; see SP 800-90A Rev. 1"
#elif SB_HMAC_DRBG_RESEED_INTERVAL < 18
// Sweet B unit tests depend on this
// Note that Sweet B does NOT support prediction resistance! If you want the
// equivalent, reseed the DRBG before every operation yourself.
#error "SB_HMAC_DRBG_RESEED_INTERVAL is nonsense"
#endif

#else
/** The number of generate calls that may be performed before a reseed is
 *  required by the DRBG. This may be overriden by the user, though the value
 *  will be checked at compile time for sanity and compliance to NIST SP
 *  800-90A Rev. 1. */
#define SB_HMAC_DRBG_RESEED_INTERVAL 1024
#endif

// These are arbitrary limits and may be overridden

#if defined(SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST)

#if SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST > 65536
#error "SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST too large; see SP 800-90A Rev. 1"
#elif SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST < 128
// Sweet B unit tests depend on being able to generate 128 bytes at a time
#error "SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST is nonsense"
#endif

#else
/** The maximum number of bytes that may be generated at one time by the DRBG.
 *  This may be overriden by the user, though the values will be checked at
 *  compile time for sanity and compliance to NIST SP 800-90A Rev. 1. */
#define SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST 1024
#endif

#if defined(SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH)

#if SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH > 0x100000000
#error "SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH too large; see SP 800-90A Rev. 1"
#elif SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH < 256
// Sweet B depends on being able to input 256 bytes of additional data
// See below; the limit is the same for entropy and additional data
#error "SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH is nonsense"
#endif

#else
/** The maximum number of bytes that may be provided as entropy at one time
 *  to the DRBG. This may be overriden by the user, though the values will be
 *  checked at compile time for sanity and compliance to NIST SP 800-90A
 *  Rev. 1. */
#define SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH 1024
#endif

#if defined(SB_HMAC_DRBG_ADD_VECTOR_LEN)
#if SB_HMAC_DRBG_ADD_VECTOR_LEN < 4
// Sweet B depends on being able to supply 4 chunks of additional data.
#error "SB_HMAC_DRBG_ADD_VECTOR_LEN is nonsense"
#endif
#else
/** Number of chunks of additional data that can be supplied to the DRBG. */
#define SB_HMAC_DRBG_ADD_VECTOR_LEN 4
#endif

// Is there a good reason to have separate limits here?

/** The maximum number of bytes that may be provided as additional input at one
 *  time to the DRBG. This may be overriden by the user, though the values
 *  will be checked at compile time for sanity and compliance to NIST SP 800-90A
 *  Rev. 1. */
#define SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH

/** The maximum number of bytes that may be provided as a personalization string
 *  to the DRBG. This may be overriden by the user, though the values will
 *  be checked at compile time for sanity and compliance to NIST SP 800-90A
 *  Rev. 1. */
#define SB_HMAC_DRBG_MAX_PERSONALIZATION_STRING_LENGTH SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH

/** @struct sb_hmac_drbg_state_t
 *  @brief Opaque state structure. You are responsible for allocating this
 *  and passing it into HMAC-DRBG functions.
 */
typedef struct sb_hmac_drbg_state_t {
    /** @privatesection */
    sb_hmac_sha256_state_t hmac; ///< Internal HMAC state
    sb_byte_t V[SB_SHA256_SIZE]; ///< Internal state; see SP 800-90A
    sb_size_t reseed_counter; ///< Used to signal when reseeding is required

#ifdef SB_TEST
    /* This dangerous field causes the DRBG to become "stuck" for the given
     * number of output calls. The "stuck" DRBG produces 0xFFFF...FFFF as its
     * output. */
    size_t dangerous_nonsense_count;

    /* This field causes the DRBG to reject calls to sb_hmac_drbg_generate
     * without any additional input supplied. */
    _Bool additional_input_required;
#endif
} sb_hmac_drbg_state_t; /**< Convenience typedef */

/**
 * Initialize a HMAC-DRBG instance with the given entropy, nonce, and
 * personalization string.
 *
 * @param [out] drbg DRBG state, allocated by the caller.
 * @param [in] entropy Entropy input, usually obtained from a system source
 * of entropy such as a hardware random number generator or \c /dev/random
 * device.
 * @param [in] entropy_len Length of entropy input, in bytes.
 * Must be at least ::SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH and less than
 * or equal to ::SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH.
 * @param [in] nonce Nonce input, usually obtained from a system source of
 * entropy such as a hardware random number generator or \c /dev/random device.
 * @param [in] nonce_len Length of nonce input, in bytes. Must be at least
 * ::SB_HMAC_DRBG_MIN_NONCE_LENGTH and less than or equal to
 * ::SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH.
 * @param [in] personalization Personalization string, used to separate DRBG
 * instances used for different purposes.
 * @param [in] personalization_len Length of personalization string, in bytes.
 * Must be less than or equal to
 * ::SB_HMAC_DRBG_MAX_PERSONALIZATION_STRING_LENGTH.
 * @return On success, ::SB_SUCCESS. ::SB_ERROR_INSUFFICIENT_ENTROPY
 * if the entropy or nonce lengths were less than the minimum values.
 * ::SB_ERROR_INPUT_TOO_LARGE if the entropy, nonce, or personalization
 * string lengths were greater than or equal to the maximum limits.
 * @memberof sb_hmac_drbg_state_t
 */
extern sb_error_t
sb_hmac_drbg_init(sb_hmac_drbg_state_t drbg[static restrict 1],
                  const sb_byte_t* entropy,
                  size_t entropy_len,
                  const sb_byte_t* nonce,
                  size_t nonce_len,
                  const sb_byte_t* personalization,
                  size_t personalization_len);

/**
 * Reseed a HMAC-DRBG instance with the given entropy input and optional
 * additional input.
 *
 * @param [in,out] drbg DRBG instance. Must previously have been initialized
 * by calling ::sb_hmac_drbg_init.
 * @param [in] entropy Entropy input, usually obtained from a system source
 * of entropy such as a hardware random number generator or \c /dev/random
 * device.
 * @param [in] entropy_len Length of entropy input, in bytes.
 * Must be at least ::SB_HMAC_DRBG_MIN_ENTROPY_INPUT_LENGTH and less than
 * or equal to ::SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH.
 * @param [in] additional Additional input, typically obtained from the
 * application. May be any value which does not require protection at a
 * higher security strength than that of the DRBG.
 * @param [in] additional_len Length of additional input, in bytes. Must be
 * less than or equal ::SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH.
 * @return On success, ::SB_SUCCESS. ::SB_ERROR_INSUFFICIENT_ENTROPY if
 * the entropy length is less than the minimum value.
 * ::SB_ERROR_INPUT_TOO_LARGE if the entropy or additional input lengths were
 * greater than or equal to the maximum limits.
 * ::SB_ERROR_DRBG_UNINITIALIZED if the DRBG has been nullified but not
 * initialized.
 * @memberof sb_hmac_drbg_state_t
 */
extern sb_error_t
sb_hmac_drbg_reseed(sb_hmac_drbg_state_t drbg[static restrict 1],
                    const sb_byte_t* entropy,
                    size_t entropy_len,
                    const sb_byte_t* additional,
                    size_t additional_len);

/**
 * Query the DRBG instance to determine whether it is possible to generate
 * input a given number of times without reseeding being required. Useful to
 * detect a reseed-required situation in advance of a batch of calls to the
 * DRBG.
 *
 * @param [in] drbg DRBG instance. Must previously have been initialized
 * by calling ::sb_hmac_drbg_init.
 * @param [in] count Number of times the DRBG generate functions will be
 * called in a given batch operation.
 * @return Indicates ::SB_SUCCESS if the DRBG generate functions may be
 * called \p count times without requiring reseeding, or
 * ::SB_ERROR_RESEED_REQUIRED if one of the batch of calls will require
 * the DRBG to be reseeded. Also returns ::SB_ERROR_DRBG_UNINITIALIZED if
 * the DRBG has been nullified but not initialized.
 * @memberof sb_hmac_drbg_state_t
 */
extern sb_error_t sb_hmac_drbg_reseed_required(sb_hmac_drbg_state_t const
                                               drbg[static 1], size_t count);

/**
 * Generate deterministic pseudo-random bits using the DRBG. You are
 * encouraged NOT to use this method and to use
 * ::sb_hmac_drbg_generate_additional_dummy if no meaningful additional
 * input is available in your application, as this method may not be
 * backtracking resistant.
 *
 * @param [in,out] drbg DRBG instance. Must previously have been initialized
 * by calling ::sb_hmac_drbg_init.
 * @param [out] output DRBG output.
 * @param [in] output_len Length of desired DRBG output. Must be
 * less than or equal to ::SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST.
 * @return On success, ::SB_SUCCESS with generated bytes in
 * output. ::SB_ERROR_REQUEST_TOO_LARGE if the output length is too large.
 * ::SB_ERROR_RESEED_REQUIRED if the DRBG must be reseeded before
 * generating random output. ::SB_ERROR_DRBG_UNINITIALIZED if the DRBG
 * has been nullified but not initialized.
 * @memberof sb_hmac_drbg_state_t
 */
extern sb_error_t
sb_hmac_drbg_generate(sb_hmac_drbg_state_t drbg[static restrict 1],
                      sb_byte_t* output,
                      size_t output_len);

/**
 * Generate deterministic pseudo-random bits using the DRBG while supplying
 * "dummy" additional input (currently, one byte with a value of 0). This
 * method SHOULD be used in preference to ::sb_hmac_drbg_generate, as
 * HMAC-DRBG may not be backtracking resistant if additional input is not
 * supplied. The additional input need not be unknown to the adversary in
 * order to obtain backtracking resistance. See
 * https://eprint.iacr.org/2018/349.pdf for more discussion on the properties
 * of HMAC-DRBG.
 *
 * @param [in,out] drbg DRBG instance. Must previously have been initialized
 * by calling ::sb_hmac_drbg_init.
 * @param [out] output DRBG output.
 * @param [in] output_len Length of desired DRBG output. Must be
 * less than or equal to ::SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST.
 * @return On success, ::SB_SUCCESS with generated bytes in
 * output. ::SB_ERROR_REQUEST_TOO_LARGE if the output length is too large.
 * ::SB_ERROR_RESEED_REQUIRED if the DRBG must be reseeded before
 * generating random output. ::SB_ERROR_DRBG_UNINITIALIZED if the DRBG
 * has been nullified but not initialized.
 * @memberof sb_hmac_drbg_state_t
 */
extern sb_error_t
sb_hmac_drbg_generate_additional_dummy
    (sb_hmac_drbg_state_t drbg[static restrict 1],
     sb_byte_t* output,
     size_t output_len);

/**
 * Generate deterministic pseudo-random bits using the DRBG. Additional input
 * is provided to the DRBG using this method as a vector of up to
 * ::SB_HMAC_DRBG_ADD_VECTOR_LEN inputs. Each non-NULL input must have
 * an associated nonzero length, and at least one input must be present. The
 * output must not alias any part of the additional data.
 *
 * @param [in,out] drbg DRBG instance. Must previously have been initialized
 * by calling ::sb_hmac_drbg_init.
 * @param [out] output DRBG output.
 * @param [in] output_len Length of desired DRBG output. Must be
 * less than or equal to ::SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST.
 * @param [in] additional A vector of ::SB_HMAC_DRBG_ADD_VECTOR_LEN
 * inputs, as pointers to byte strings, with lengths supplied in
 * additional_len.
 * @param [in] additional_len A vector of ::SB_HMAC_DRBG_ADD_VECTOR_LEN
 * additional input lengths, corresponding to the inputs in the additional
 * parameter.
 * @return On success, ::SB_SUCCESS with generated bytes in output.
 * ::SB_ERROR_REQUEST_TOO_LARGE if the output length is too large.
 * ::SB_ERROR_INPUT_TOO_LARGE if the sum of the additional input lengths is
 * greater than ::SB_HMAC_DRBG_MAX_ADDITIONAL_INPUT_LENGTH.
 * ::SB_ERROR_ADDITIONAL_INPUT_REQUIRED if no additional input is present.
 * ::SB_ERROR_RESEED_REQUIRED if the DRBG must be reseeded before
 * generating random output. ::SB_ERROR_DRBG_UNINITIALIZED if the DRBG
 * has been nullified but not initialized.
 * @memberof sb_hmac_drbg_state_t
 */
extern sb_error_t sb_hmac_drbg_generate_additional_vec
    (sb_hmac_drbg_state_t drbg[static restrict 1],
     sb_byte_t* restrict output, size_t output_len,
     const sb_byte_t* const additional[static SB_HMAC_DRBG_ADD_VECTOR_LEN],
     const size_t additional_len[static SB_HMAC_DRBG_ADD_VECTOR_LEN]);

#endif
