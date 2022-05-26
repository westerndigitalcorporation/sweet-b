/** @file sb_types.h
 *  @brief public API for common types
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

#ifndef SB_TYPES_H
#define SB_TYPES_H

#include <stdint.h>

/** The number of bytes in a 256-bit value. */
#define SB_ELEM_BYTES 32

/* SB_WORD_SIZE was previously called SB_MUL_SIZE, as the primary effect is
 * to control the width of multiplication operations used in Sweet B. Provide
 * compatibility with the previous definition. */
#if defined(SB_MUL_SIZE) && defined(SB_WORD_SIZE) && SB_MUL_SIZE != SB_WORD_SIZE
#error "SB_WORD_SIZE and deprecated SB_MUL_SIZE conflict."
#elif defined(SB_MUL_SIZE) && !defined(SB_WORD_SIZE)
#define SB_WORD_SIZE SB_MUL_SIZE
#endif

#if !defined(SB_WORD_SIZE)
/** @brief SB_WORD_SIZE controls the width of primitive arithmetic operands
 * used in Sweet B, such as addition, subtraction, and multiplication. It is
 * set in terms of bytes. The default value is 4, but you should set this as
 * appropriate for the resources of your processor. For instance, if your
 * processor features a multiplier that can produce a 64-bit result from two
 * 32-bit operands, then set ::SB_WORD_SIZE to 4. By default, ::SB_WORD_SIZE
 * is set to the size (in bytes) of uintptr_t.
 */

#if UINTPTR_MAX == UINT64_MAX
#define SB_WORD_SIZE 8
#elif UINTPTR_MAX == UINT32_MAX
#define SB_WORD_SIZE 4
#elif UINTPTR_MAX == UINT16_MAX
#define SB_WORD_SIZE 2
#else
/* What kind of system is this? */
#define SB_WORD_SIZE 1
#endif
#endif

/** @brief Used to indicate "a bunch of bytes" instead of "an 8-bit integer
 * we're doing arithmetic on"
 */
typedef uint8_t sb_byte_t;

/** @struct sb_single_t
 *  @brief A single 256-bit (32-byte) value.
 */
typedef struct sb_single_t {
    /** An array 32 bytes making up the 256-bit value. */
    sb_byte_t bytes[SB_ELEM_BYTES];
} sb_single_t; /**< Convenience typedef */

/** @struct sb_double_t
 *  @brief Two 256-bit values in one wrapper.
 */
typedef struct sb_double_t {
    /** An array of 64 bytes making up two 256-bit values. */
    sb_byte_t bytes[SB_ELEM_BYTES * 2];
} sb_double_t; /**< Convenience typedef */

/** @enum sb_data_endian_value_t
 *  @brief Used to indicate whether input data is in big-endian or
 *  little-endian format.
 */
typedef enum sb_data_endian_value_t {
    SB_DATA_ENDIAN_LITTLE = 0, ///< Little endian data.
    SB_DATA_ENDIAN_BIG         ///< Big endian data.
} sb_data_endian_value_t; /**< Convenience typedef */

/** @brief Wrapper 32-bit integer type for ::sb_data_endian_value_t, used for
 *  ABI compatibility purposes. */
typedef uint32_t sb_data_endian_t;

/**
 * @brief Error return type used in Sweet B.
 * Functions which return errors in Sweet B may return a bitwise-or of multiple
 * error values, defined in ::sb_error_value_t. For example, when
 * initializing a HMAC-DRBG instance, if the supplied entropy input is too
 * small and the supplied personalization string is too large, the return
 * value will be ::SB_ERROR_INSUFFICIENT_ENTROPY | ::SB_ERROR_INPUT_TOO_LARGE.
*/

typedef uint32_t sb_error_t;

// TODO: is it worth making sb_error_t a uint64_t?

/** @brief Error values. */
typedef enum sb_error_value_t {
    /** No error has occurred and the output parameters are valid. */
        SB_SUCCESS = 0,

    /** The entropy input used to seed the DRBG is too small */
        SB_ERROR_INSUFFICIENT_ENTROPY = 1u << 0u,

    /** The input to the DRBG is too large */
        SB_ERROR_INPUT_TOO_LARGE = 1u << 1u,

    /** The DRBG generate request is too large */
        SB_ERROR_REQUEST_TOO_LARGE = 1u << 2u,

    /** The DRBG must be reseeded and the operation can be retried */
        SB_ERROR_RESEED_REQUIRED = 1u << 3u,

    /** The DRBG has produced an extremely low-probability output (p < 2^-64) */
        SB_ERROR_DRBG_FAILURE = 1u << 4u,

    /** The curve supplied is invalid */
        SB_ERROR_CURVE_INVALID = 1u << 5u,

    /** The supplied private key is invalid */
        SB_ERROR_PRIVATE_KEY_INVALID = 1u << 6u,

    /** The supplied public key is invalid */
        SB_ERROR_PUBLIC_KEY_INVALID = 1u << 7u,

    /** The signature is invalid */
        SB_ERROR_SIGNATURE_INVALID = 1u << 8u,

    /** The DRBG has not been nullified but not initialized */
        SB_ERROR_DRBG_UNINITIALIZED = 1u << 9u,

    /** The context was initialized by a \c _start routine that does not match
     *  the \c _continue or \c _finish routine being called. */
        SB_ERROR_INCORRECT_OPERATION = 1u << 10u,

    /** The \c _finish routine was called, but the operation was not yet
     *  finished. */
        SB_ERROR_NOT_FINISHED = 1u << 11u,

    /** Additional input was required by the DRBG, but not provided. */
        SB_ERROR_ADDITIONAL_INPUT_REQUIRED = 1u << 12u,
} sb_error_value_t;

/* Non-public definitions used in private context structures follow. These
 * are defined in public headers for size and alignment purposes only. */

/** @privatesection */

/** @typedef sb_word_t
    @brief A word of size ::SB_WORD_SIZE bytes, used for underlying
    field element arithmetic. */

/** @def SB_FE_WORDS
    @brief The number of ::SB_WORD_SIZE sized words needed to represent
    a field element of size ::SB_ELEM_BYTES */

#if SB_WORD_SIZE == 8

typedef uint64_t sb_word_t;
#define SB_FE_WORDS 4

#elif SB_WORD_SIZE == 4

typedef uint32_t sb_word_t;
#define SB_FE_WORDS 8

#elif SB_WORD_SIZE == 2

typedef uint16_t sb_word_t;
#define SB_FE_WORDS 16

#elif SB_WORD_SIZE == 1

typedef uint8_t sb_word_t;
#define SB_FE_WORDS 32

#else
#error "SB_WORD_SIZE is invalid"
#endif

/** @struct sb_fe_t
    @brief  Used to represent a field element as a set of ::SB_FE_WORDS
    words of ::SB_WORD_SIZE length. */
typedef struct sb_fe_t {
    sb_word_t words[SB_FE_WORDS]; ///< Words which represent the field element
#if defined(SB_FE_VERIFY_QR) && SB_FE_VERIFY_QR != 0
    _Bool qr, qr_always;
    const struct sb_prime_field_t* p;
#endif
} sb_fe_t; /**< Convenience typedef */

#if !defined(SB_FE_VERIFY_QR) || SB_FE_VERIFY_QR == 0
_Static_assert(sizeof(sb_fe_t) == SB_ELEM_BYTES, "sizeof(sb_fe_t) must be "
                                                 "SB_ELEM_BYTES");
#endif

/** @struct sb_fe_pair_t
 *  @brief  Used to represent a point on a curve as X, Y coordinates. */
typedef struct sb_fe_pair_t {
    sb_fe_t x, ///< The X coordinate of the point.
            y; ///< The Y coordinate of the point.
} sb_fe_pair_t; /**< Convenience typedef */

/** This is used for internal sizes, even if the platform native size_t is
 *  64 bits */
typedef uint32_t sb_size_t;

#endif
