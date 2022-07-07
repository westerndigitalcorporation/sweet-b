/** @file sb_fe.c
 *  @brief constant time prime-field element operations
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
#include "sb_fe.h"
#include "sb_sw_curves.h"

// Convert an appropriately-sized set of bytes (src) into a field element
// using the given endianness.
void sb_fe_from_bytes(sb_fe_t dest[static const restrict 1],
                      const sb_byte_t src[static const restrict SB_ELEM_BYTES],
                      const sb_data_endian_t e)
{
    sb_wordcount_t src_i = 0;
    if (e == SB_DATA_ENDIAN_LITTLE) {
        src_i = SB_ELEM_BYTES - 1;
    }
    for (sb_wordcount_t i = 0; i < SB_FE_WORDS; i++) {
        sb_word_t t = 0;
        for (sb_wordcount_t j = 0; j < (SB_WORD_BITS / 8); j++) {
#if SB_WORD_SIZE != 1
            t <<= (sb_word_t) 8;
#endif
            t |= src[src_i];
            if (e == SB_DATA_ENDIAN_LITTLE) {
                src_i--;
            } else {
                src_i++;
            }
        }
        SB_FE_WORD(dest, SB_FE_WORDS - 1 - i) = t;
    }

    SB_FE_UNQR(dest);
}

// Convert a field element into bytes using the given endianness.
void sb_fe_to_bytes(sb_byte_t dest[static const restrict SB_ELEM_BYTES],
                    const sb_fe_t src[static const restrict 1],
                    const sb_data_endian_t e)
{
    sb_wordcount_t dest_i = 0;
    if (e == SB_DATA_ENDIAN_LITTLE) {
        dest_i = SB_ELEM_BYTES - 1;
    }
    for (sb_wordcount_t i = 0; i < SB_FE_WORDS; i++) {
        sb_word_t t = SB_FE_WORD(src, SB_FE_WORDS - 1 - i);
        for (sb_wordcount_t j = 0; j < (SB_WORD_BITS / 8); j++) {
            dest[dest_i] = (sb_byte_t) (t >> (SB_WORD_BITS - 8));
#if SB_WORD_SIZE != 1
            t <<= (sb_word_t) 8;
#endif
            if (e == SB_DATA_ENDIAN_LITTLE) {
                dest_i--;
            } else {
                dest_i++;
            }
        }
    }
}

#if !SB_FE_ASM
/* These helpers are only used in C source. */

// Returns an all-0 or all-1 word given a boolean flag 0 or 1 (respectively)
static inline sb_word_t sb_word_mask(const sb_word_t a)
{
    SB_ASSERT((a == 0 || a == 1), "word used for ctc must be 0 or 1");
    return (sb_word_t) -a;
}

// Used to select one of b or c in constant time, depending on whether a is 0 or 1
// ctc is an abbreviation for "constant time choice"
static inline sb_word_t sb_ctc_word(const sb_word_t a,
                                    const sb_word_t b,
                                    const sb_word_t c)
{
    return (sb_word_t) (((sb_uword_t) sb_word_mask(a) &
                         ((sb_uword_t) b ^ (sb_uword_t) c)) ^ (sb_uword_t) b);
}

static inline sb_uword_t sb_fe_nonneg_word_mask(const sb_bitcount_t a,
                                                const sb_bitcount_t b)
{
    const sb_bitcount_t d = a - b;
    const sb_bitcount_t d_neg = (d >> (sb_bitcount_t) SB_FE_BITS_BITS);
    const sb_bitcount_t d_nonneg = d_neg ^(sb_bitcount_t) 1;
    return (sb_uword_t) d_nonneg;

}

/* The following functions are defined in assembly if assembly support is
 * provided. */

sb_word_t sb_fe_equal(const sb_fe_t left[static const 1],
                      const sb_fe_t right[static const 1])
{
    sb_word_t r = 0;

    SB_UNROLL_3(i, 0, {
        // Accumulate any bit differences between left_i and right_i into r
        // using bitwise OR
        r |= SB_FE_WORD(left, i) ^ SB_FE_WORD(right, i);
    });
    // r | -r has bit SB_WORD_BITS - 1 set if r is nonzero
    // v ^ 1 is logical negation
    // This incredibly ugly mess of casts prevents any use of bitwise
    // operations on signed values.
    r = (sb_word_t) ((((sb_uword_t) (sb_word_t) ((sb_uword_t) r |
                                                 ((sb_uword_t) -r)))
        >> (sb_uword_t) (SB_WORD_BITS - 1)) ^ (sb_uword_t) 1);

    return r;
}

// Returns 1 if the bit is set, 0 otherwise
// While testing of bits set at secret indices in field elements should not
// occur, this operation is still written in timing-independent fashion to
// hide the source of the resulting bit from the compiler as best we can.
sb_word_t
sb_fe_test_bit(const sb_fe_t a[static const 1], const sb_bitcount_t bit)
{
    sb_uword_t r = 0;
    const sb_bitcount_t word_bit = bit & SB_WORD_BITS_MASK;

    // Note that the result is accumulated into the low bit of r, but the
    // other bits may be junk until the end, when they are masked off.

    SB_UNROLL_3(i, 0, {
        const sb_bitcount_t l = ((sb_bitcount_t) i) << SB_WORD_BITS_SHIFT;
        const sb_bitcount_t h = l + SB_WORD_BITS - 1;
        // first iteration: l = 0; h = SB_WORD_BITS - 1
        // second iteration: l = SB_WORD_BITS; h = SB_WORD_BITS * 2 - 1
        // h - bit is negative if h < bit
        // bit - l is negative if l > bit
        // if bit - l is non-negative and h - bit is non-negative, then
        // l <= bit <= h
        const sb_uword_t we =
            (sb_word_t) (((sb_uword_t) SB_FE_WORD(a, i)) >> word_bit);
        const sb_uword_t l_mask = sb_fe_nonneg_word_mask(bit, l);
        const sb_uword_t h_mask = sb_fe_nonneg_word_mask(h, bit);
        r |= ((sb_uword_t) (we & l_mask) & h_mask);
    });

    return (sb_word_t) (r & (sb_uword_t) 1);
}

// Add the given field elements and store the result in dest, which MAY alias
// left or right. The carry is returned.

sb_word_t sb_fe_add(sb_fe_t dest[static const 1],
                    const sb_fe_t left[static const 1],
                    const sb_fe_t right[static const 1])
{
    sb_word_t carry = 0;

    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) +
                             (sb_dword_t) SB_FE_WORD(right, i) +
                             (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });

    SB_FE_UNQR(dest);
    return carry;
}

// Subtract the given field elements and store the result in dest, which MAY
// alias left or right. The borrow is returned.
sb_word_t sb_fe_sub_borrow(sb_fe_t dest[static const 1],
                           const sb_fe_t left[static const 1],
                           const sb_fe_t right[static const 1],
                           sb_word_t borrow)
{

    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                             ((sb_dword_t) SB_FE_WORD(right, i) +
                              (sb_dword_t) borrow);
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });

    SB_FE_UNQR(dest);
    return borrow;
}

sb_word_t sb_fe_lt(const sb_fe_t left[static 1],
                   const sb_fe_t right[static 1])
{
    sb_word_t borrow = 0;

    SB_UNROLL_3(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                             ((sb_dword_t) SB_FE_WORD(right, i) +
                              (sb_dword_t) borrow);
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });

    return borrow;
}

// This helper routine subtracts p if c is 1; the subtraction is done
// unconditionally, and the result is only written if c is 1
void sb_fe_cond_sub_p(sb_fe_t dest[static const restrict 1],
                      sb_word_t c,
                      const sb_fe_t p[static const restrict 1])
{
    sb_word_t borrow = 0;

    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(dest, i) -
                             ((sb_dword_t) SB_FE_WORD(p, i) +
                              (sb_dword_t) borrow);
        SB_FE_WORD(dest, i) = sb_ctc_word(c, SB_FE_WORD(dest, i),
                                          (sb_word_t) d);
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });

    SB_FE_UNQR(dest);
}


// This helper adds 1 or (p + 1), depending on c. On ARM, this is done by
// adding p then choosing to store either the original value or the result of
// the addition, followed by a second pass to add 1.
void sb_fe_cond_add_p_1(sb_fe_t dest[static const restrict 1],
                        sb_word_t c,
                        const sb_fe_t p[static const restrict 1])
{
    sb_word_t carry = 1;

    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(dest, i) +
                             (sb_dword_t) sb_ctc_word(c, 0, SB_FE_WORD(p, i)) +
                             (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });

    SB_FE_UNQR(dest);
}

// Swap `a` and `b` if `c` is true using constant-time choice.
void sb_fe_ctswap(sb_word_t c,
                  sb_fe_t a[static const restrict 1],
                  sb_fe_t b[static const restrict 1])
{
    SB_UNROLL_3(i, 0, {
        const sb_word_t t = sb_ctc_word(c, SB_FE_WORD(a, i), SB_FE_WORD(b, i));
        SB_FE_WORD(b, i) = sb_ctc_word(c, SB_FE_WORD(b, i), SB_FE_WORD(a, i));
        SB_FE_WORD(a, i) = t;
    });
}

#endif

/* Field element subtraction without incoming borrow. */
sb_word_t sb_fe_sub(sb_fe_t dest[static const 1],
                    const sb_fe_t left[static const 1],
                    const sb_fe_t right[static const 1])
{
    return sb_fe_sub_borrow(dest, left, right, 0);
}

// Quasi-reduce dest (with extra carry bit) by subtracting p iff dest is
// greater than p. The input precondition to this function is as follows:
// 0 < (carry | dest) <= 2 * p
// where | denotes concatenation, not bitwise or.
static void sb_fe_qr(sb_fe_t dest[static const restrict 1],
                     sb_word_t const carry,
                     const sb_prime_field_t p[static const restrict 1])
{
    const sb_word_t b = sb_fe_lt(&p->p, dest);
    sb_fe_cond_sub_p(dest, carry | b, &p->p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "quasi-reduction must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "quasi-reduction must always produce quasi-reduced output");

    SB_FE_QR(dest, p);
}

// Quasi-reduce the input, under the assumption that 2 * p > 2^SB_FE_BITS or
// that the input < 2 * p. The input range is [0, 2^SB_FE_BITS - 1].
void sb_fe_mod_reduce(sb_fe_t dest[static const restrict 1],
                      const sb_prime_field_t p[static const restrict 1])
{
#ifdef SB_DEBUG_ASSERTS
    for (sb_bitcount_t i = SB_FE_BITS - 1; i >= p->bits; i--) {
        SB_ASSERT(!sb_fe_test_bit(dest, i),
                  "input must be the same bit-width as the prime!");
    }
#endif
    // Add 1 and capture the overflow. Input range is now [1, 2^SB_FE_BITS].
    const sb_word_t c = sb_fe_add(dest, dest, &SB_FE_ONE);

    // Use quasi-reduction restoration to fully quasi-reduce the input.
    sb_fe_qr(dest, c, p);

    // Use modular subtraction to subtract 1.
    sb_fe_mod_sub(dest, dest, &SB_FE_ONE, p);
}

// Un-quasi-reduce the input, under the assumption that the input is already
// quasi-reduced and thus in the range [1, p]
void sb_fe_mod_reduce_full(sb_fe_t dest[static const restrict 1],
                           const sb_prime_field_t p[static const restrict 1])
{
    SB_FE_ASSERT_QR(dest, p);

    // c is 0 iff dest < p
    const sb_word_t c = sb_fe_lt(dest, &p->p) ^ 1;

    sb_fe_cond_sub_p(dest, c, &p->p);
}

// Given quasi-reduced left and right, produce quasi-reduced left - right.
// This is done as a subtraction of (right - 1) followed by addition of
// 1 or (p + 1), which means that a result of all zeros is never written back
// to memory.
void sb_fe_mod_sub(sb_fe_t dest[static const 1],
                   const sb_fe_t left[static const 1],
                   const sb_fe_t right[static const 1],
                   const sb_prime_field_t p[static const 1])
{
    SB_FE_ASSERT_QR(left, p);
    SB_FE_ASSERT_QR(right, p);
    const sb_word_t b = sb_fe_sub_borrow(dest, left, right, 1);
    sb_fe_cond_add_p_1(dest, b, &p->p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "modular subtraction must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "modular subtraction must always produce quasi-reduced output");
    SB_FE_QR(dest, p);
}

// dest = p - left mod n

void sb_fe_mod_negate(sb_fe_t dest[static const 1],
                      const sb_fe_t left[static const 1],
                      const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_sub(dest, &p->p, left, p);
}

// Given quasi-reduced left and right, produce quasi-reduced left + right.

void
sb_fe_mod_add(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1])
{
    SB_FE_ASSERT_QR(left, p);
    SB_FE_ASSERT_QR(right, p);
    sb_word_t carry = sb_fe_add(dest, left, right);
    sb_fe_qr(dest, carry, p);
}

void sb_fe_mod_double(sb_fe_t dest[static const 1],
                      const sb_fe_t left[static const 1],
                      const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_add(dest, left, left, p);
}

// bits must be < SB_WORD_BITS
// as used, this is one or two
// Shifts the value a to the right bits number of times.
static void sb_fe_rshift_w(sb_fe_t a[static const 1], const sb_bitcount_t bits)
{
    sb_word_t carry = 0;

    SB_ASSERT(bits < SB_WORD_BITS, "invalid shift in sb_fe_rshift_w");

    for (size_t i = SB_FE_WORDS - 1; i <= SB_FE_WORDS; i--) {
        sb_word_t word = SB_FE_WORD(a, i);
        SB_FE_WORD(a, i) = (sb_word_t) (((sb_uword_t) word >> bits) |
                                        (sb_uword_t) carry);
        carry = (sb_word_t) (word << (SB_WORD_BITS - bits));
    }

    SB_FE_UNQR(a);
}

// Halve the input. Assumes input is quasi-reduced and may be equal to p
void sb_fe_mod_halve(sb_fe_t dest[static const 1],
                     const sb_fe_t left[static const 1],
                     sb_fe_t temp[static const 1],
                     const sb_prime_field_t p[static const 1])
{
    SB_FE_ASSERT_QR(left, p);

    const sb_word_t low = sb_fe_test_bit(left, 0);

    *temp = *left;
    *dest = *temp;
    sb_fe_rshift_w(dest, 1); // left = left / 2

    // The following uses non-modular subtraction. If the input is p,
    // the additive inversion of p will be 0; shifting this right by
    // one bit and then subtracting from p again will restore the value p
    sb_fe_sub(temp, &p->p, temp); // temp = -temp    
    sb_fe_rshift_w(temp, 1); // temp = temp / 2
    sb_fe_sub(temp, &p->p, temp); // temp = -temp    

    // if the low bit is 0, left has the correct answer; otherwise temp does
    sb_fe_ctswap(low, dest, temp);

    SB_FE_QR(dest, p);
}

#if !SB_FE_ASM
/* If assembly is provided, sb_fe_mont_mult is defined in assembly. */

// This helper is the equivalent of a single ARM DSP instruction:
// (h, l) = a * b + c + d
static inline void sb_mult_add_add(sb_word_t h[static const restrict 1],
                                   sb_word_t l[static const restrict 1],
                                   const sb_word_t a,
                                   const sb_word_t b,
                                   const sb_word_t c,
                                   const sb_word_t d)
{
    const sb_dword_t t =
        ((sb_dword_t) a * (sb_dword_t) b) + (sb_dword_t) c + (sb_dword_t) d;
    *h = (sb_word_t) (t >> (SB_WORD_BITS));
    *l = (sb_word_t) t;
}

static inline void sb_add_carry_2(sb_word_t h[static const restrict 1],
                                  sb_word_t l[static const restrict 1],
                                  const sb_word_t a,
                                  const sb_word_t b,
                                  const sb_word_t c)
{
    const sb_dword_t r = (sb_dword_t) a + (sb_dword_t) b + (sb_dword_t) c;
    *h = (sb_word_t) (r >> SB_WORD_BITS);
    *l = (sb_word_t) r;
}

// Montgomery multiplication: given x, y, p produces x * y * R^-1 mod p where
// R = 2^256 mod p. See the _Handbook of Applied Cryptography_ by Menezes,
// van Oorschot, and Vanstone, chapter 14, section 14.3.2:
// http://cacr.uwaterloo.ca/hac/about/chap14.pdf
void sb_fe_mont_mult(sb_fe_t A[static const restrict 1],
                     const sb_fe_t x[static const 1],
                     const sb_fe_t y[static const 1],
                     const sb_prime_field_t p[static const 1])
{
    SB_FE_ASSERT_QR(x, p);
    SB_FE_ASSERT_QR(y, p);

    /*
     * HAC gives the algorithm for Montgomery multiplication as follows:
     *
     * 1: A := 0
     * 2: For i from 0 to (n - 1) do:
     * 2.1: u_i := (a_0 + x_i * y_0) * m' mod b
     * 2.2:   A := (A + x_i * y + u_i * m) / b
     * 3: If A >= m then A := A - m
     * 4: Return A
     *
     * The algorithm is implemented below as follows:
     *
     * 1. A := 0; hw := 0
     * 2. For i from 0 to (n - 1) do:
     * 2.1:        (c, A) := A + x_i * y where c is the (word-sized) carry
     * 2.2:           u_i := a_0 * m' mod b
     * 2.3:       (c2, A) := A + u_i * m where c2 is the word-sized carry
     * 2.4:             A := A / b (truncating division, or one word shift)
     * 2.5: (hw, A_(n-1)) := c + c2 + hw where hw is the (single bit) carry
     * 3: If A > m or hw = 1 then A := A - m
     * 4: Return A
     *
     * In this implementation, A consists of N words of b bits, and an
     * additional bit "hw". During steps 2.1 and 2.3, A is extended to N + 1
     * words, and the highest order word is stored separately. At step 2.5,
     * the incoming carry "hw" and each of the two high order words (c and
     * c2) are summed, and this forms the carry for the next iteration of the
     * loop. At the conclusion of the loop, if the carry is set, the prime m
     * must be subtracted from A.
     *
     * Notably in step 2.1 the first step performed is a_0 := a_0 + x_i * y_0
     * This means that at step 2.2, a_0 can be used directly, and x_i * y_0
     * does not need to be recomputed.
     */

    sb_word_t hw = 0;

    SB_UNROLL_2(i, 0, { // for i from 0 to (n - 1)
        const sb_word_t x_i = SB_FE_WORD(x, i);

        sb_word_t c = 0, c2 = 0;

        SB_UNROLL_1(j, 0, {
            // On the first iteration, A is 0
            const sb_word_t A_j = (i == 0) ? 0 : SB_FE_WORD(A, j);
            // A = A + x_i * y
            sb_mult_add_add(&c, &SB_FE_WORD(A, j), x_i, SB_FE_WORD(y, j),
            A_j, c);
        });

        // u_i = (a_0 + x_i y_0) m' mod b
        const sb_word_t u_i =
            (sb_word_t)
                (SB_FE_WORD(A, 0) *
                 ((sb_uword_t) p->p_mp));

        SB_UNROLL_1(j, 0, {
            // A = A + u_i * m
            sb_mult_add_add(&c2, &SB_FE_WORD(A, j), u_i,
                            SB_FE_WORD(&p->p, j), SB_FE_WORD(A, j),
                            c2);
        });

        // A = A / b
        SB_UNROLL_1(j, 1, { SB_FE_WORD(A, j - 1) = SB_FE_WORD(A, j); });

        sb_add_carry_2(&hw, &SB_FE_WORD(A, SB_FE_WORDS - 1), hw, c, c2);
        SB_ASSERT(hw < 2, "W + W * W + W * W overflows at most once");
    });

    // If A > p or hw is set, A = A - p

    sb_fe_qr(A, hw, p);
}

#endif

// Montgomery squaring: dest = left * left * R^-1 mod p
void sb_fe_mont_square(sb_fe_t dest[static const restrict 1],
                       const sb_fe_t left[static const 1],
                       const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, left, p);
}

// Montgomery reduction: dest = left * R^-1 mod p, implemented by Montgomery
// multiplication by 1.
void sb_fe_mont_reduce(sb_fe_t dest[static const restrict 1],
                       const sb_fe_t left[static const 1],
                       const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, &SB_FE_ONE, p);
}

// Montgomery domain conversion: dest = left * R mod p, implemented by
// Montgomery multiplication by R^2 mod p.
void sb_fe_mont_convert(sb_fe_t dest[static const restrict 1],
                        const sb_fe_t left[static const 1],
                        const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, &p->r2_mod_p, p);
}

// x = x^e mod m

// Modular exponentiation is NOT constant time with respect to the exponent;
// this procedure is used ONLY for inversion and square roots, and the
// exponents are determined by the prime in this case. It is assumed that
// performance may differ with respect to the curve, but not with respect to
// the inputs.

// The lowest e_shift bits of the exponent e are skipped in the modular
// exponentiation; in other words, x := x ^ (e >> e_shift) mod p
static void
sb_fe_mod_expt_r(sb_fe_t x[static const restrict 1],
                 const sb_fe_t e[static const restrict 1],
                 const sb_word_t e_shift,
                 sb_fe_t t2[static const restrict 1],
                 sb_fe_t t3[static const restrict 1],
                 const sb_prime_field_t p[static const restrict 1])
{
    _Bool by = 0;
    *t2 = p->r_mod_p;
    for (sb_bitcount_t i = p->bits - 1; i >= e_shift && i <= SB_FE_BITS; i--) {
        const sb_word_t b = sb_fe_test_bit(e, i);
        if (!by) {
            if (b) {
                by = 1;
            } else {
                continue;
            }
        }
        sb_fe_mont_square(t3, t2, p);
        if (b) {
            sb_fe_mont_mult(t2, t3, x, p);
        } else {
            *t2 = *t3;
        }
    }
    *x = *t2;
}

// See sb_prime_field_t in sb_fe.h for more comments on modular inversion.
void sb_fe_mod_inv_r(sb_fe_t dest[static const restrict 1],
                     sb_fe_t t2[static const restrict 1],
                     sb_fe_t t3[static const restrict 1],
                     const sb_prime_field_t p[static const restrict 1])
{
    sb_fe_mod_expt_r(dest, &p->p_minus_two_f1, 0, t2, t3, p);
    sb_fe_mod_expt_r(dest, &p->p_minus_two_f2, 0, t2, t3, p);
}

static _Bool sb_fe_mod_sqrt_r(sb_fe_t x[static const restrict 1],
                              sb_fe_t t1[static const restrict 1],
                              sb_fe_t t2[static const restrict 1],
                              sb_fe_t t3[static const restrict 1],
                              sb_fe_t t4[static const restrict 1],
                              const sb_prime_field_t p[static const restrict 1])
{
    if ((SB_FE_WORD(&p->p, 0) & (sb_word_t) 0x3) != 3) {
        return 0;
    }
    *t1 = p->p;
    sb_fe_add(t1, t1, &SB_FE_ONE); // t1 = p + 1
    *t4 = *x; // t4 = x * R
    sb_fe_mod_expt_r(x, t1, 2, t2, t3, p); // x = (t4 ^ (p + 1) / 4) * R
    sb_fe_mont_square(t3, x, p); // t3 = x ^ 2 * R
    return sb_fe_equal(t3, t4);
}

_Bool sb_fe_mod_sqrt(sb_fe_t x[static const restrict 1],
                     sb_fe_t t1[static const restrict 1],
                     sb_fe_t t2[static const restrict 1],
                     sb_fe_t t3[static const restrict 1],
                     sb_fe_t t4[static const restrict 1],
                     const sb_prime_field_t p[static const restrict 1])
{
    sb_fe_mont_convert(t4, x, p);
    *x = *t4;
    const _Bool rv = sb_fe_mod_sqrt_r(x, t1, t2, t3, t4, p);
    sb_fe_mont_reduce(t4, x, p);
    *x = *t4;
    return rv;
}

#ifdef SB_TEST

#define SB_FE_TESTS_IMPL
#include "sb_fe_tests.c.h"

#endif
