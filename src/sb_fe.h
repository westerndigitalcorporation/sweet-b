/** @file sb_fe.h
 *  @brief private API for constant time prime-field element operations
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

#ifndef SB_FE_H
#define SB_FE_H

#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include "sb_types.h"
#include "sb_time.h"

/** @name Field element implementation
  *
  * The following types implement arithmetic over the underlying prime field,
  * i.e. Z//p for some prime.
  *
  * Field element definitions are private and are not declared in the
  * public header files. These routines perform a limited amount of input
  * checking and cannot be relied upon for the level of robustness provided
  * by the public Sweet B API.
  *
  * As a ZVA countermeasure, modular operations work with "quasi-reduced" inputs
  * and outputs: rather than reducing to [0, M - 1], they reduce to [1, M].
  * While 0 may appear as an intermediary due to the borrow/carry
  * implementation, Z blinding (Coron's third countermeasure) should ensure
  * that an attacker can't cause such an intermediary product deliberately.
  *
  * This applies to P-256; for secp256k1, there is no (0, Y) point on the curve.
  * Similarly, for curve25519, zero values will only occur when dealing with
  * a small-order subgroup of the curve. Fortuitously (or not?), P-256's prime
  * has a Hamming weight very close to 256/2, which may make analyses more
  * difficult, though the zero limbs might still be detectable. During
  * Montgomery multiplication of a Hamming-weight-128 field element by P, most
  * of the intermediaries have hamming weight close to the original, with P
  * only emerging in the last iteration of the loop.
  *
  * @{
  */

typedef sb_size_t sb_wordcount_t;
typedef sb_size_t sb_bitcount_t;

/** @brief The number of bits in a field element. Currently fixed at 256. */
#define SB_FE_BITS  256

/** @brief The number of bits in the number of bits in a field element. */
#define SB_FE_BITS_BITS 8

// These are defined in sb_types.h so that sb_fe_t can be defined in a public
// header for size and alignment purposes. They are documented here because
// they are non-public.

/** @typedef sb_word_t
 *  @brief An unsigned integer used for primitive arithmetic operations, of the
 *  width defined by ::SB_WORD_SIZE .
 */

/** @var SB_FE_WORDS
 *  @brief The number of words required to implement a 256-bit field element.
 */

/** @struct sb_fe_t
 *  @brief A field element is a 256-bit natural represented as ::SB_FE_WORDS
 *  words, each of ::SB_WORD_SIZE bytes. Field elements may be reduced or
 *  unreduced; modular operations guarantee the reduction of their outputs,
 *  but primitive arithmetic operations operate on unreduced values.
 */

/** @var sb_fe_t::words
 *  @brief The words making up the value, in big-endian order (most
 *  significant word first).
 */

/* The following definitions differ depending on the value of SB_WORD_SIZE. */

/** @var sb_dword_t
 *  @brief An unsigned integer type double the width of a ::sb_word_t.
 *  Used to represent the result of certain arithmetic operations.
 */

/** @def SB_WORD_C
 *  @brief Like \c UINTnn_C, but for an integer constant the size of a
 *  ::sb_word_t.
 */

/** @def SB_WORD_MAX
 *  @brief Like \c UINTnn_MAX, but for an integer the size of a ::sb_word_t.
 */

/** @def SB_WORD_BITS
 *  @brief The number of bits in a ::sb_word_t.
 */

/** @def SB_WORD_BITS_SHIFT
 *  @brief Log base 2 of ::SB_WORD_BITS.
 */

/** @def SB_WORD_BITS_MASK
 *  @brief Used as a mask to determine which in word a given bit of a
 *  ::sb_fe_t resides.
 */

/** @def SB_WORD_EXPAND
 *  @brief Given an unsigned 64-bit integer constant, expand to a comma
 *  separated list of C constant values containing the same value in multiple
 *  ::sb_word_t values. Used for ::SB_FE_CONST .
 */

#if SB_WORD_SIZE == 8

#if !defined(__SIZEOF_INT128__) ||  __SIZEOF_INT128__ != 16
#error "SB_WORD_SIZE is 8, but your platform does not appear to define __uint128_t"
#endif

typedef __uint128_t sb_dword_t;

#define SB_WORD_C(v) UINT64_C(v)
#define SB_WORD_MAX UINT64_MAX

static const sb_bitcount_t SB_WORD_BITS = 64;
static const sb_word_t SB_WORD_BITS_SHIFT = 6;
static const sb_word_t SB_WORD_BITS_MASK = 0x3F;

#define SB_WORD_EXPAND(d) d

#elif SB_WORD_SIZE == 4

typedef uint64_t sb_dword_t;

#define SB_WORD_C(v) UINT32_C(v)
#define SB_WORD_MAX UINT32_MAX

static const sb_bitcount_t SB_WORD_BITS = 32;
static const sb_word_t SB_WORD_BITS_SHIFT = 5;
static const sb_word_t SB_WORD_BITS_MASK = 0x1F;

#define SB_WORD_EXPAND(d) (sb_word_t) (d), (sb_word_t) ((d) >> UINT64_C(32))

#elif SB_WORD_SIZE == 2

typedef uint32_t sb_dword_t;

#define SB_WORD_C(v) UINT16_C(v)
#define SB_WORD_MAX UINT16_MAX

static const sb_bitcount_t SB_WORD_BITS = 16;
static const sb_word_t SB_WORD_BITS_SHIFT = 4;
static const sb_word_t SB_WORD_BITS_MASK = 0x0F;

#define SB_WORD_EXPAND(d) (sb_word_t) ((d) >> UINT64_C(0)), \
                          (sb_word_t) ((d) >> UINT64_C(16)), \
                          (sb_word_t) ((d) >> UINT64_C(32)), \
                          (sb_word_t) ((d) >> UINT64_C(48))

#elif SB_WORD_SIZE == 1

typedef uint16_t sb_dword_t;

#define SB_WORD_C(v) UINT8_C(v)
#define SB_WORD_MAX UINT8_MAX

static const sb_bitcount_t SB_WORD_BITS = 8;
static const sb_word_t SB_WORD_BITS_SHIFT = 3;
static const sb_word_t SB_WORD_BITS_MASK = 0x07;

#define SB_WORD_EXPAND(d) (sb_word_t) ((d) >> UINT64_C(0)), \
                          (sb_word_t) ((d) >> UINT64_C(8)), \
                          (sb_word_t) ((d) >> UINT64_C(16)), \
                          (sb_word_t) ((d) >> UINT64_C(24)), \
                          (sb_word_t) ((d) >> UINT64_C(32)), \
                          (sb_word_t) ((d) >> UINT64_C(40)), \
                          (sb_word_t) ((d) >> UINT64_C(48)), \
                          (sb_word_t) ((d) >> UINT64_C(56))

#else

#error "SB_WORD_SIZE is invalid"

#endif

/** @var sb_uword_t
 *  @brief This type is either sb_word_t or unsigned int, whichever is
 *  larger. It exists to prevent implicit cast-to-int problems. */

/** @fn SB_UWORD_C(v)
 *  @brief Like \c UINTnn_C, but for a sb_uword_t integer constant.
 */

#if SB_WORD_MAX < UINT_MAX
typedef unsigned int sb_uword_t;
#define SB_UWORD_C(v) (v ## u)
#else
typedef sb_word_t sb_uword_t;
#define SB_UWORD_C(v) SB_WORD_C(v)
#endif

/** @var SB_UNROLL
 *  @brief Controls the level of unrolling applied to loops in Sweet B.
 *
 *  The following values are possible:
 *
 *  - At level 0, no unrolling is performed. This provides the worst
 *  performance but the most compact code.
 *
 *  - At level 1, the inner field-element multiplication loop is unrolled. This
 *  provides a good performance benefit with small impact on code size.
 *
 *  - At level 2, the outer field-element multiplication loop and inner loop are
 *  unrolled, along with field element additive and subtractive operations.
 *  This provides most of the possible unrolling performance benefit with modest
 *  impact on code size.
 *
 *  - At level 3, all of the above unrolling is applied, and field element
 *  comparisons are also unrolled. This provides maximum speed but little
 *  benefit above level 2.
 *
 *  The default level of unrolling is 1. However, on platforms where ARM
 *  assembly is provided, the field-element additive operations are always
 *  unrolled regardless of the value of this preprocessor variable, as this has
 *  little code space impact but significant performance benefit.
 */
#if !defined(SB_UNROLL)
#define SB_UNROLL 1
#endif

// This nonsense defines a set macros that repeat a statement a given number
// of times.

#define SB_REPEAT_2(...) __VA_ARGS__; __VA_ARGS__
#define SB_REPEAT_4(...) SB_REPEAT_2(__VA_ARGS__); SB_REPEAT_2(__VA_ARGS__)
#define SB_REPEAT_8(...) SB_REPEAT_4(__VA_ARGS__); SB_REPEAT_4(__VA_ARGS__)
#define SB_REPEAT_16(...) SB_REPEAT_8(__VA_ARGS__); SB_REPEAT_8(__VA_ARGS__)
#define SB_REPEAT_32(...) SB_REPEAT_16(__VA_ARGS__); SB_REPEAT_16(__VA_ARGS__)

// Note: when porting to a new compiler, check to see if it's smart enough to
// optimize out dead code when v >= SB_FE_WORDS! Dead code will occur when
// the initial index of the unrolled loop is nonzero; currently this only
// once, with an initial index of 1, resulting in one dead statement.

// The token pasting of c and c2 is used to produce the appropriate
// SB_REPEAT_n for the number of words in a field element, depending on the
// size of sb_word_t.
#if SB_UNROLL > 0
#define SB_UNROLL_WORDS__(c, c2, v, i, ...) do { \
    sb_bitcount_t v = (i); \
    c ## c2(if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++); \
} while (0)

// This annoying bit of indirection forces SB_FE_WORDS to be expanded before
// it is pasted to the token SB_REPEAT_
#define SB_UNROLL_WORDS_(...) SB_UNROLL_WORDS__(__VA_ARGS__)

#define SB_UNROLL_WORDS(...) SB_UNROLL_WORDS_(SB_REPEAT_, SB_FE_WORDS, \
                                              __VA_ARGS__)
#endif

#define SB_LOOP_WORDS(v, i, ...) \
    do { for (size_t v = (i); v < SB_FE_WORDS; v++) __VA_ARGS__ } while (0)

#if SB_UNROLL >= 1
#define SB_UNROLL_1(v, i, ...) SB_UNROLL_WORDS(v, i, __VA_ARGS__)
#else
#define SB_UNROLL_1(v, i, ...) SB_LOOP_WORDS(v, i, __VA_ARGS__)
#endif

#if SB_UNROLL >= 2
#define SB_UNROLL_2(v, i, ...) SB_UNROLL_WORDS(v, i, __VA_ARGS__)
#else
#define SB_UNROLL_2(v, i, ...) SB_LOOP_WORDS(v, i, __VA_ARGS__)
#endif

#if SB_UNROLL >= 3
#define SB_UNROLL_3(v, i, ...) SB_UNROLL_WORDS(v, i, __VA_ARGS__)
#else
#define SB_UNROLL_3(v, i, ...) SB_LOOP_WORDS(v, i, __VA_ARGS__)
#endif

#if SB_UNROLL > 3
#error "SB_UNROLL must be between 0 and 3 (inclusive)."
#endif

/** @brief Helper macro for a constant field element value.
 *
 *  Given the 64-bit unsigned constants \p w3, \p w2, \p w1, \p w0,
 *  expands to a ::sb_fe_t initializer appropriate for the size of
 *  ::sb_word_t using the ::SB_WORD_EXPAND macro. For example, \c
 *  SB_FE_CONST(0, 0, 0, 1) is the 256-bit representation of the value 1.
 */
#define SB_FE_CONST(w3, w2, w1, w0) \
    { .words = { SB_WORD_EXPAND(UINT64_C(w0)), SB_WORD_EXPAND(UINT64_C(w1)), \
                 SB_WORD_EXPAND(UINT64_C(w2)), SB_WORD_EXPAND(UINT64_C(w3)) }}


/** @var SB_FE_VERIFY_QR
 *  @brief Quasi-reduction runtime verification. If ::SB_FE_VERIFY_QR is
 *  defined as non-zero, then field elements track which prime they have been
 *  quasi-reduced to (if any), and modular operations enforce this as a
 *  precondition. Note that this does not verify the values are within range;
 *  rather, it verifies that reduction-preserving and non-reduction-
 *  preserving operations are not incorrectly mixed.
 */

#ifndef SB_FE_VERIFY_QR
#define SB_FE_VERIFY_QR 0
#endif

// SB_FE_VERIFY_QR can only be used when executing unit tests.
#if SB_FE_VERIFY_QR && !defined(SB_TEST)
#error "SB_FE_VERIFY_QR is invalid outside of unit tests"
#endif

/** @def SB_FE_CONST_QR(w3, w2, w1, w0, prime)
 *  @brief Helper macro for a constant field element value. Like
 *  ::SB_FE_CONST, but defines a constant that is quasi-reduced with respect to
 *  some prime field.
 */

/** @def SB_FE_CONST_ALWAYS_QR(w3, w2, w1, w0)
 *  @brief Helper macro for a constant field element value. Like
 *  ::SB_FE_CONST, but asserts that the value is always quasi-reduced with
 *  respect to any prime. Used for small constants (namely, ::SB_FE_ONE).
 */

#if SB_FE_VERIFY_QR != 0
#define SB_FE_CONST_QR(w3, w2, w1, w0, prime) \
    { .words = { SB_WORD_EXPAND(UINT64_C(w0)), SB_WORD_EXPAND(UINT64_C(w1)), \
                 SB_WORD_EXPAND(UINT64_C(w2)), SB_WORD_EXPAND(UINT64_C(w3)) }, \
      .qr = 1, .p = (prime) }
#define SB_FE_CONST_ALWAYS_QR(w3, w2, w1, w0) \
    { .words = { SB_WORD_EXPAND(UINT64_C(w0)), SB_WORD_EXPAND(UINT64_C(w1)), \
                 SB_WORD_EXPAND(UINT64_C(w2)), SB_WORD_EXPAND(UINT64_C(w3)) }, \
      .qr_always = 1 }
#else
#define SB_FE_CONST_QR(w3, w2, w1, w0, prime) SB_FE_CONST(w3, w2, w1, w0)
#define SB_FE_CONST_ALWAYS_QR(w3, w2, w1, w0) SB_FE_CONST(w3, w2, w1, w0)
#endif

/** @brief Return the given word of a field element. */
#define SB_FE_WORD(fe, i) ((fe)->words[i])

/** @brief Return the given word of a field element as a ::sb_uword_t. */
#define SB_FE_UWORD(fe, i) ((sb_uword_t) SB_FE_WORD(fe, i))

/** @var SB_FE_ONE
  * @brief The value 1, as a field element. */
static const sb_fe_t SB_FE_ONE = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 1);

/** @brief The value 0, as a field element. */
static const sb_fe_t SB_FE_ZERO = SB_FE_CONST(0, 0, 0, 0);

/** @def SB_FE_UNQR(fe)
 *  @brief Establishes that the field element is no longer quasi-reduced. Used
 *  for quasi-reduction invariant checking with ::SB_FE_VERIFY_QR.
 */

/** @def SB_FE_QR(fe, prime)
 *  @brief Establishes that the field element is now quasi-reduced with respect
 *  to some specific prime. Used for quasi-reduction invariant checking with
 *  ::SB_FE_VERIFY_QR.
 */

/** @def SB_FE_ASSERT_QR(fe, prime)
 *  @brief Asserts that the field element is quasi-reduced with respect to
 *  the given prime. This can be satisfied in one of three ways: the element
 *  is always quasi-reduced (as in ::SB_FE_ONE), the element is
 *  quasi-reduced with respect to the given prime, or the element is
 *  quasi-reduced with respect to a prime which is less than the given prime
 *  (which is used in short Weierstrass signature verification).
 */

#if SB_FE_VERIFY_QR != 0
#define SB_FE_UNQR(fe) do { \
    (fe)->qr = 0; \
    (fe)->qr_always = 0; \
    (fe)->p = NULL; \
} while (0)

#define SB_FE_QR(fe, prime) do { \
    (fe)->qr = 1; (fe)->p = (prime); \
} while (0)

#define SB_FE_ASSERT_QR(fe, prime) \
    SB_ASSERT((fe)->qr_always || \
              ((fe)->qr && (fe)->p == (prime)) || \
              ((fe)->qr && sb_fe_lt(&(fe)->p->p, &(prime)->p)), \
    "fe must be quasi-reduced!")
#else
#define SB_FE_UNQR(fe) do { } while (0)
#define SB_FE_QR(fe, prime) do { } while (0)
#define SB_FE_ASSERT_QR(fe, prime) do { } while (0)
#endif

/** @var SB_FE_ASM
 *  @brief If ::SB_FE_ASM is defined as non-zero, then assembly support
 *  for Sweet B is assumed to be supplied.
 *
 *  The following routines will not be defined by \c sb_fe.c and must be
 *  supplied by assembly:
 *    - ::sb_fe_equal
 *    - ::sb_fe_test_bit
 *    - ::sb_fe_add
 *    - ::sb_fe_sub_borrow
 *    - ::sb_fe_lt
 *    - ::sb_fe_cond_sub_p
 *    - ::sb_fe_cond_add_p_1
 *    - ::sb_fe_ctswap
 *    - ::sb_fe_mont_mult
 *
 *  Currently, assembly support implies that ::SB_WORD_SIZE is equal to 4.
 *  Additionally, ::SB_FE_VERIFY_QR conflicts with layout assumptions made
 *  by the assembly code, and so must be disabled when assembly is enabled.
 */

#ifndef SB_FE_ASM
#define SB_FE_ASM 0
#endif

#if SB_FE_ASM && SB_FE_VERIFY_QR
#error "SB_FE_VERIFY_QR can't be enabled compiling with assembly"
#endif

#if SB_FE_ASM && SB_WORD_SIZE != 4
#error "SB_WORD_SIZE must be 4 when compiling with assembly"
#endif

/** @brief The definition of a prime field.
 *
 * Sweet B uses Montgomery multiplication. As such,
 * ::sb_prime_field_t::p_mp, ::sb_prime_field_t::r_mod_p and
 * ::sb_prime_field_t::r2_mod_p are used to store parameters for Montgomery
 * multiplication and Montgomery domain conversion.
 *
 * Inversion mod p uses Fermat's little theorem: n^-1 == n^(p-2) mod p
 * Inversion does not need to be constant time with respect to the chosen
 * prime, and as such it's best to use exponents with a minimum Hamming
 * weight. Thus, we compute (n^f_1)^f_2 where (f_1 * f_2) = p - 2.
 * You can optimize inversion routines with more intermediate products
 * than this approach, but this works "well enough" for our purposes.
 */
typedef struct sb_prime_field_t {
    /** The prime as a ::sb_fe_t value. */
    sb_fe_t p;

    /** -(p^-1) mod M, where M is the size of ::sb_word_t . */
    sb_word_t p_mp;

    /** First factor of p - 2, used for Fermat's little theorem based
     *  inversion. */
    sb_fe_t p_minus_two_f1;

    /** Second factor of p - 2. */
    sb_fe_t p_minus_two_f2;

    /** 2^(SB_FE_BITS * 2) mod p */
    sb_fe_t r2_mod_p;

    /** 2^SB_FE_BITS mod p */
    sb_fe_t r_mod_p;

    /** The number of bits in the prime. */
    sb_bitcount_t bits;
} sb_prime_field_t; /**< Convenience typedef */

// Assembly assumes that p_mp is at a fixed offset based on the size of sb_fe_t.
#if SB_FE_ASM
_Static_assert(offsetof(sb_prime_field_t, p_mp) == SB_ELEM_BYTES,
    "sb_prime_field_t layout invariant broken; assembly will not function "
    "correctly");
#endif

/**
 * @brief Bytes to field element conversion.
 *
 * Given a set of bytes, convert it to a field element using the supplied
 * endianness \p e.
 *
 * @param [out] dest The resulting field element.
 * @param [in] src The ::SB_ELEM_BYTES representing the field element in the
 * endianness \p e.
 * @param [in] e The endianness of the input bytes.
 */
extern void sb_fe_from_bytes(sb_fe_t dest[static restrict 1],
                             const sb_byte_t src[static restrict SB_ELEM_BYTES],
                             sb_data_endian_t e);

/**
 * @brief Field element to bytes conversion.
 *
 * Given a field element, convert it to a set of bytes using the supplied
 * endinanness \p e.
 *
 * @param [out] dest The resulting set of ::SB_ELEM_BYTES bytes.
 * @param [in] src The field element.
 * @param [in] e The endianness of the output bytes.
 */
extern void sb_fe_to_bytes(sb_byte_t dest[static restrict SB_ELEM_BYTES],
                           const sb_fe_t src[static restrict 1],
                           sb_data_endian_t e);

/**
 * @brief Constant-time field element equality.
 *
 * In constant time, return whether two field elements are strictly equal.
 * This is not a modular equality procedure; field elements should be reduced
 * before comparison when comparing modulo some prime p.
 *
 * @param [in] left First field element to compare.
 * @param [in] right Second field element to compare.
 * @return 1 if the field elements are equal, or 0 if they differ. The
 * comparison is timing invariant.
 */
extern sb_word_t sb_fe_equal(const sb_fe_t left[static 1],
                             const sb_fe_t right[static 1]);

/**
 * @brief Test whether a given bit is set in a field element.
 *
 * @param [in] a The field element to test.
 * @param [in] bit The bit to test. Must be less than ::SB_FE_BITS.
 * @return The bit at position \p bit in the field element \p a.
 */
extern sb_word_t sb_fe_test_bit(const sb_fe_t a[static 1], sb_bitcount_t bit);

/**
 * @brief Constant-time field element addition.
 *
 * Add two field elements, returning a carry value.
 *
 * @param [in,out] dest The destination field element. May alias \p left or
 * \p right.
 * @param [in] left The first field element to add.
 * @param [in] right The second field element to add.
 * @return 0 if there was no carry from the addition, or 1 if there was a carry.
 */
extern sb_word_t sb_fe_add(sb_fe_t dest[static 1],
                           const sb_fe_t left[static 1],
                           const sb_fe_t right[static 1]);

/**
 * @brief Constant-time field element subtraction with borrow.
 *
 * Subtract two field elements, accepting an incoming borrow, and returning a
 * borrow value.
 *
 * @param [in,out] dest The destination field element. May alias \p left or
 * \p right.
 * @param [in] left The field element to subtract \p right from.
 * @param [in] right The field element to be subtracted from \p left.
 * @param [in] borrow Incoming borrow for the subtraction. Logically added to
 * \p right.
 * @return 0 if there was no borrow from the subtraction, or 1 if there was a
 * borrow.
 */
extern sb_word_t sb_fe_sub_borrow(sb_fe_t dest[static 1],
                                  const sb_fe_t left[static 1],
                                  const sb_fe_t right[static 1],
                                  sb_word_t borrow);

/**
 * @brief Constant-time field element subtraction.
 *
 * Subtract two field elements, returning a borrow value.
 *
 * @param [in,out] dest The destination field element. May alias \p left or
 * \p right.
 * @param [in] left The field element to subtract \p right from.
 * @param [in] right The field element to be subtracted from \p left.
 * @return 0 if there was no borrow from the subtraction, or 1 if there was a
 * borrow.
 */
extern sb_word_t sb_fe_sub(sb_fe_t dest[static 1],
                           const sb_fe_t left[static 1],
                           const sb_fe_t right[static 1]);

/**
 * @brief Constant-time subtraction of p iff c is 1.
 *
 * If \p c is 1, subtract \p p from \p dest, storing the result in \p dest.
 *
 * @param [in,out] dest The destination field element. May not alias \p p.
 * @param [in] c The condition. Must be 0 or 1.
 * @param [in] p The value to be subtracted from \p dest.
 */
extern void sb_fe_cond_sub_p(sb_fe_t dest[static restrict 1],
                             sb_word_t c,
                             const sb_fe_t p[static restrict 1]);

/**
 * @brief Constant-time addition of 1 or p + 1.
 *
 * If \p c is 1, add \p p + 1 to \p dest; otherwise, add 1.
 *
 * @param [in,out] dest The destination field element. May not alias \p p.
 * @param [in] c The condition. Must be 0 or 1.
 * @param [in] p The value to be added to \p dest.
 */
extern void sb_fe_cond_add_p_1(sb_fe_t dest[static restrict 1],
                               sb_word_t c,
                               const sb_fe_t p[static restrict 1]);

/**
 * @brief Constant-time less-than comparison.
 *
 * In constant time, compute whether \p left is less than \p right.
 *
 * @param [in] left The left side of the comparison.
 * @param [in] right The right side of the comparison.
 * @return 1 if left is less than right, or 0 otherwise.
 */
extern sb_word_t sb_fe_lt(const sb_fe_t left[static 1],
                          const sb_fe_t right[static 1]);

/**
 * @brief Constant-time conditional field-element swap.
 *
 * In constant time and with regular memory access, swap \p b and \p c if and
 * only if \p a is 1.
 *
 * @param [in] a Flag to determine whether the swap should be carried out.
 * Must be 0 or 1.
 * @param [in,out] b First value to swap.
 * @param [in,out] c Second value to swap.
 */
extern void sb_fe_ctswap(sb_word_t a,
                         sb_fe_t b[static restrict 1],
                         sb_fe_t c[static restrict 1]);

/**
 * @brief Constant-time modular quasi-reduction.
 *
 * Values in Sweet B are quasi-reduced to a range of [1, p] instead of
 * [0, p - 1] to mitigate zero-value attacks (ZVA). In constant time,
 * computes the quasi-reduction of the \c p->bits bit natural \p dest.
 *
 * @param [in,out] dest The field element to be quasi-reduced, and where the
 * output value will be stored.
 * @param [in] p The prime field to compute the quasi-reduction with respect to.
 */
extern void sb_fe_mod_reduce(sb_fe_t dest[static restrict 1],
                             const sb_prime_field_t p[static restrict 1]);

/**
 * @brief Constant-time modular full reduction.
 * 
 * Restores a quasi-reduced value in the range [1, p] to one that is
 * reduced to the range [0, p - 1].
 * 
 * @param [in,out] dest The field element to be fully reduced.
 * @param [in] p The prime field to compute the reduction with respect to.
 */
extern void sb_fe_mod_reduce_full(sb_fe_t dest[static restrict 1],
                                  const sb_prime_field_t p[static restrict 1]);

/**
 * @brief Constant-time modular addition.
 *
 * Places the quasi-reduced result of the modular addition \p left + \p right
 * mod \p p in \p dest.
 *
 * @param [out] dest Result of the modular addition. May alias \p left or \p
 * right.
 * @param [in] left The first field element to add.
 * @param [in] right The second field element to add.
 * @param [in] p The prime field for the modular operation.
 */

extern void sb_fe_mod_add(sb_fe_t dest[static 1],
                          const sb_fe_t left[static 1],
                          const sb_fe_t right[static 1],
                          const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time modular doubling.
 *
 * Places the quasi-reduced result of the modular doubling 2 * \p left in \p
 * dest.
 *
 * @param [out] dest Result of the modular doubling. May alias \p left.
 * @param [in] left The value to be doubled.
 * @param [in] p The prime field for the modular operation.
 */

extern void sb_fe_mod_double(sb_fe_t dest[static 1],
                             const sb_fe_t left[static 1],
                             const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time modular halving.
 *
 * Places the quasi-reduced result of the modular halving \p left / 2 in \p
 * dest.
 *
 * @param [out] dest Result of the modular halving. May alias \p left.
 * @param [in] left The value to be halved.
 * @param [in] temp A temporary field element to use in the computation.
 * @param [in] p The prime field for the modular operation.
 */

extern void sb_fe_mod_halve(sb_fe_t dest[static 1],
                            const sb_fe_t left[static 1],
                            sb_fe_t temp[static 1],
                            const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time modular subtraction.
 *
 * Places the quasi-reduced result of the modular subtraction \p left - \p
 * right mod \p p in \p dest.
 *
 * @param [out] dest Result of the modular subtraction. May alias \p left or
 * \p right.
 * @param [in] left The field element to subtract \p right from.
 * @param [in] right The field element to be subtracted from \p left.
 * @param [in] p The prime field for the modular operation.
 */
extern void sb_fe_mod_sub(sb_fe_t dest[static 1],
                          const sb_fe_t left[static 1],
                          const sb_fe_t right[static 1],
                          const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time modular additive inversion (negation).
 *
 * Places the quasi-reduced result of the modular subtraction \p p - \p
 * left mod \p p in \p dest.
 *
 * @param [out] dest Result of the modular negation. May alias \p left.
 * @param [in] left The field element to subtract from \p p.
 * @param [in] p The prime field for the modular operation.
 */

extern void sb_fe_mod_negate(sb_fe_t dest[static 1],
                             const sb_fe_t left[static 1],
                             const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time Montgomery multiplication.
 *
 * Computes \p left * \p right * R^-1 mod \p p, where R is the value defined
 * in ::sb_prime_field_t::r_mod_p.
 *
 * @param [out] dest Result of the Montgomery multiplication. Must not alias
 * \p left or \p right.
 * @param [in] left First value to be multiplied.
 * @param [in] right Second value to be multiplied.
 * @param [in] p The prime field for the Montgomery multiplication.
 */

extern void sb_fe_mont_mult(sb_fe_t dest[static restrict 1],
                            const sb_fe_t left[static 1],
                            const sb_fe_t right[static 1],
                            const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time Montgomery squaring.
 *
 * Computes \p left ^ 2 * R^-1 mod \p p, where R is the value defined in
 * sb_prime_field_t::r_mod_p.
 *
 * @param [out] dest Result of the Montgomery squaring. Must not alias \p left.
 * @param [in] left Value to be squared.
 * @param [in] p The prime field for the Montgomery multiplication.
 */

extern void sb_fe_mont_square(sb_fe_t dest[static restrict 1],
                              const sb_fe_t left[static 1],
                              const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time conversion to the Montgomery domain.
 *
 * Multiplies \p left by R mod \p p, where R is the value defined in
 * sb_prime_field_t::r_mod_p. Used to add a factor of R before Montgomery
 * multiplication.
 *
 * @param [out] dest Result of the Montgomery multiplication. Must not alias
 * \p left.
 * @param [in] left Value to be reduced.
 * @param [in] p The prime field for the Montgomery multiplication.
 */
extern void sb_fe_mont_convert(sb_fe_t dest[static restrict 1],
                               const sb_fe_t left[static 1],
                               const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time Montgomery reduction.
 *
 * Multiplies \p left by R^-1 mod \p p, where R is the value defined in
 * sb_prime_field_t::r_mod_p. Used to remove a factor of R after Montgomery
 * multiplication.
 *
 * @param [out] dest Result of the Montgomery multiplication. Must not alias
 * \p left.
 * @param [in] left Value to be reduced.
 * @param [in] p The prime field for the Montgomery multiplication.
 */
extern void sb_fe_mont_reduce(sb_fe_t dest[static restrict 1],
                              const sb_fe_t left[static 1],
                              const sb_prime_field_t p[static 1]);

/**
 * @brief Constant-time modular inversion in the Montgomery domain.
 *
 * Given a Montgomery-domain value in \p dest, compute its modular inverse \p
 * dest ^ -1 in the Montgomery domain using helper storage \p t2 and \p t3.
 * This procedure is constant time with respect to the input value in \p
 * dest, but not with respect to the prime field. Inversion uses Fermat's
 * little theorem; see ::sb_prime_field_t for more details.
 *
 * @param [in,out] dest Value to be inverted, and where the result of the
 * inversion is stored.
 * @param [out] t2 Helper storage to be used during the inversion.
 * @param [out] t3 Helper storage to be used during the inversion.
 * @param [in] p The prime field for the multiplicative inversion.
 */
extern void sb_fe_mod_inv_r(sb_fe_t dest[static restrict 1],
                            sb_fe_t t2[static restrict 1],
                            sb_fe_t t3[static restrict 1],
                            const sb_prime_field_t p[static restrict 1]);

/**
 * @brief Constant time modular square root.
 *
 * Given a value in \p dest, compute its modular square root with respect to
 * the prime field \p p using helper storage \p t1, \p t2, \p t3, and \p t4.
 * This procedure is constant time with respect to the input value in \p
 * dest, but not with respect to the prime field. This operation will always
 * fail if \p p is not equal to 3 mod 4. Returns true if the square root was
 * computed, or false if the input does not have a square root or if the
 * prime was not equal to 3 mod 4.
 *
 * @param [in,out] dest Value to have its square root computed, and where
 * the result of the square root is stored.
 * @param [out] t1 Helper storage to be used during the square root.
 * @param [out] t2 Helper storage to be used during the square root.
 * @param [out] t3 Helper storage to be used during the square root.
 * @param [out] t4 Helper storage to be used during the square root.
 * @param [in] p The prime field for the square root operation.
 */
extern _Bool sb_fe_mod_sqrt(sb_fe_t dest[static restrict 1],
                            sb_fe_t t1[static restrict 1],
                            sb_fe_t t2[static restrict 1],
                            sb_fe_t t3[static restrict 1],
                            sb_fe_t t4[static restrict 1],
                            const sb_prime_field_t p[static restrict 1]);

/** @} */

#endif
