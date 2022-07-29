/** @file sb_fe_tests.c.h
 *  @brief tests for constant time prime-field element operations
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

#ifdef SB_FE_TESTS_IMPL

/*
 * Tests basic field element functionality. Makes sure addition and subtraction,
 * as well as their respective carries/borrows work as expected.
 *
 * Operations tested:
 *  0 - 1 triggers a borrow.
 *  check that every word of 0 - 1 is = -1
 *  Test that -1 + 1 triggers a carry and is equal to 0.
 *  Test that 0x7fff...ffff * 2 = 0xefff...ffff does not trigger a carry.
 *  Test that 0xefff...ffff + 1 = 0xffff...ffff does not trigger a carry.
 *  Test that 0xffff...ffff + 1 does trigger a carry and is equal to 0.
 */
_Bool sb_test_fe(void)
{
    sb_fe_t res;
    SB_TEST_ASSERT(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    for (size_t i = 0; i < SB_FE_WORDS; i++) {
        SB_TEST_ASSERT(SB_FE_WORD(&res, i) == (sb_word_t) -1);
    }
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    SB_TEST_ASSERT(sb_fe_equal(&res, &SB_FE_ZERO));

    // all 0xFF
    SB_TEST_ASSERT(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    sb_fe_rshift_w(&res, 1);
    // 0xEFFF.....FFFF
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &res) == 0);
    // 0xFFFF.....FFFF
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 0);
    // 0
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    SB_TEST_ASSERT(sb_fe_equal(&res, &SB_FE_ZERO));
    return 1;
}

/*
 * Tests modular doubling and halving operations.
 */
_Bool sb_test_mod_double(void)
{
    sb_fe_t a, b;
    a = SB_FE_ONE;
    SB_FE_QR(&a, &SB_CURVE_P256_P);

    // (1 / 2) * 2 = 1
    sb_fe_mod_halve(&a, &a, &b, &SB_CURVE_P256_P);
    sb_fe_mod_double(&a, &a, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&a, &SB_FE_ONE));

    // (1 * 2) / 2 = 1
    sb_fe_mod_double(&a, &a, &SB_CURVE_P256_P);
    sb_fe_mod_halve(&a, &a, &b, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&a, &SB_FE_ONE));

    // 0 / 2 = 0
    a = SB_CURVE_P256_P.p;
    sb_fe_mod_halve(&a, &a, &b, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&a, &SB_CURVE_P256_P.p));

    // 0 * 2 = 0
    sb_fe_mod_double(&a, &a, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&a, &SB_CURVE_P256_P.p));

    // (-1 / 2) * 2 + 1 = 0
    a = SB_CURVE_P256_P.p;
    sb_fe_mod_sub(&a, &a, &SB_FE_ONE, &SB_CURVE_P256_P);
    sb_fe_mod_halve(&a, &a, &b, &SB_CURVE_P256_P);
    sb_fe_mod_double(&a, &a, &SB_CURVE_P256_P);
    sb_fe_mod_add(&a, &a, &SB_FE_ONE, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&a, &SB_CURVE_P256_P.p));

    return 1;
}

/*
 * Tests Montgomery multiplication to ensure that: the computation is
 * correct and the value is correctly reduced mod p after multiplication.
 * Recall mont_mult(x, y, p) = xy * R^-1 mod p where R = 2^|p| is fixed.
 *
 * Operations tested:
 *  1^2 = R^-1 mod p
 *  1 * R = 1 mod p
 *  R^2 * 1 = R mod p
 *  R^2 * R^-1 = 1 mod p
 *  n * R^2 = n * R mod p (uses mont_reduce to compare against n)
 *  R^2 * 1 = R mod n
 *  a5 * p = p mod p = 0 (a5 is defined below)
 */
_Bool sb_test_mont_mult(void)
{
    static const sb_fe_t p256_r_inv =
        SB_FE_CONST_QR(0xFFFFFFFE00000003, 0xFFFFFFFD00000002,
                       0x00000001FFFFFFFE, 0x0000000300000000,
                       &SB_CURVE_P256_P);
    sb_fe_t t = SB_FE_ZERO;

    sb_fe_t r = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_fe_sub(&r, &r, &SB_CURVE_P256_P.p) == 1); // r = R mod P
    SB_FE_QR(&r, &SB_CURVE_P256_P);

    sb_fe_mont_square(&t, &SB_FE_ONE, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &p256_r_inv));
    // aka R^-1 mod P

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p,
                    &p256_r_inv, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_t t2, np;
    np = SB_CURVE_P256_N.p;
    SB_FE_QR(&np, &SB_CURVE_P256_P);
    sb_fe_mont_mult(&t2, &np, &SB_CURVE_P256_P.r2_mod_p,
                    &SB_CURVE_P256_P);
    sb_fe_mont_reduce(&t, &t2, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p));

    r = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_fe_sub(&r, &r, &SB_CURVE_P256_N.p) == 1); // r = R mod N
    SB_TEST_ASSERT(sb_fe_equal(&r, &SB_CURVE_P256_N.r_mod_p));
    SB_FE_QR(&r, &SB_CURVE_P256_N);

    sb_fe_mont_mult(&t, &SB_CURVE_P256_N.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    static const sb_fe_t a5 = SB_FE_CONST_QR(0xAA55AA55AA55AA55,
                                             0x55AA55AA55AA55AA,
                                             0xAA55AA55AA55AA55,
                                             0x55AA55AA55AA55AA,
                                             &SB_CURVE_P256_P);

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.p, &a5,
                    &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_P.p));
    return 1;
}

/*
 * Montgomery Multiplication Overflow - manually tested values to ensure all
 * iterations trigger an overflow at some point. Overflows triggered at the
 * end of iteration i. To show that this overflows it is necessary to alter
 * the mont_mult function to show that hw = 1 at the iterations shown.
 *
 * Let:
 *
 * x1 = 0xFFFFFFFF00000001 0x0000000000000000
 *      0x00000000FFFFFFFF 0xFFFFFFFFFFFFFFFF (this is p256's p value)
 *
 * x2 = 0x00000004FFFFFFFD 0xFFFFFFFFFFFFFFFE
 *      0xFFFFFFFBFFFFFFFF 0x0000000000000003 (this is r^2 mod p for p256)
 *
 * x3 = 0x0000000000000000 0x0000000000000000
 *      0x0000FFFF00000000 0x0000000000000000
 *
 * x4 = 0xFFFFFFFF00000000 0x0000000000000000
 *      0x0000000000000000 0x0000000000000003
 *
 * y1 = 0xAA55AA55AA55AA55 0x55AA55AA55AA55AA
 *      0xAA55AA55AA55AA55 0x55AA55AA55AA55AA
 *
 * y2 = 0xFFFFFFFE00000003 0xFFFFFFFD00000002
 *      0x00000001FFFFFFFE 0x0000000300000000 (this is r^-1 mod p for p256)
 *
 * For 16-bit words:
 * x1 * y1 triggers an overflow at i = 0, 1, 2, 3 (also 4)
 * x2 * y2 triggers an overflow at i = 4, 5, 8, 9, 10, 11, 12, 13
 * x3 * y1 triggers an overflow at i = 6, 7
 * x4 * y2 triggers an overflow at i = 14, 15
 *
 * For 32-bit words:
 * x1 * y1 triggers an overflow at i = 0, 1
 * x2 * y2 triggers an overflow at i = 2, 4, 5, 6
 * x3 * y1 triggers an overflow at i = 3
 * x4 * y2 triggers an overflow at i = 7
 *
 * For 64-bit words:
 * x1 * y1 triggers an overflow at i = 0
 * x2 * y2 triggers an overflow at i = 2
 * x3 * y1 triggers an overflow at i = 1
 * x4 * y2 triggers an overflow at i = 3
 */
_Bool sb_test_mont_mult_overflow(void)
{
    static const sb_fe_t x3 = SB_FE_CONST_QR(0x0000000000000000,
                                             0x0000000000000000,
                                             0x0000FFFF00000000,
                                             0x0000000000000000,
                                             &SB_CURVE_P256_P);

    static const sb_fe_t x4 = SB_FE_CONST_QR(0xFFFFFFFF00000000,
                                             0x0000000000000000,
                                             0x0000000000000000,
                                             0x0000000000000003,
                                             &SB_CURVE_P256_P);

    static const sb_fe_t y1 = SB_FE_CONST_QR(0xAA55AA55AA55AA55,
                                             0x55AA55AA55AA55AA,
                                             0xAA55AA55AA55AA55,
                                             0x55AA55AA55AA55AA,
                                             &SB_CURVE_P256_P);

    static const sb_fe_t y2 = SB_FE_CONST_QR(0xFFFFFFFE00000003,
                                             0xFFFFFFFD00000002,
                                             0x00000001FFFFFFFE,
                                             0x0000000300000000,
                                             &SB_CURVE_P256_P);
    sb_fe_t t;
    //x1 * y1
    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.p, &y1, &SB_CURVE_P256_P);

    //x2  * y2
    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p, &y2, &SB_CURVE_P256_P);

    //x3 * y1
    sb_fe_mont_mult(&t, &x3, &y1, &SB_CURVE_P256_P);

    //x4 * y2
    sb_fe_mont_mult(&t, &x4, &y2, &SB_CURVE_P256_P);

    return 1;
}

// Handles the conversion to the Montgomery domain before passing to the
// actual modular exponentiation function and handles Montgomery reduction
// to return the value back to the caller.
static void
sb_fe_mod_expt(sb_fe_t x[static const 1], const sb_fe_t e[static const 1],
               sb_fe_t t2[static const 1], sb_fe_t t3[static const 1],
               const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(t2, x, &p->r2_mod_p, p);
    *x = *t2;
    sb_fe_mod_expt_r(x, e, 0, t2, t3, p);
    sb_fe_mont_mult(t2, x, &SB_FE_ONE, p);
    *x = *t2;
}

// Fast modular inversion using Fermat's little theorem as well as two
// precomputed low Hamming weight factors such that f1 * f2 = p - 2.
static void sb_fe_mod_inv(sb_fe_t dest[static const 1],
                          sb_fe_t t2[static const 1],
                          sb_fe_t t3[static const 1],
                          const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_expt(dest, &p->p_minus_two_f1, t2, t3, p);
    sb_fe_mod_expt(dest, &p->p_minus_two_f2, t2, t3, p);
}

/*
 * Tests that modular exponentiation in the multiplicative group works as
 * expected.
 *
 * Operations tested:
 *  2^32 = known 2^32
 *  n^p = n
 *  n^1 = n
 *  (p - 1)^-1 = p - 1
 *  inverse of 1 = 1
 *  mont_mult(b^-1 * R, b, p) = b^-1 * R * b * R^-1 mod p = 1
 *  mont_mult(b^-1 * R, b, n) = b^-1 * R * b * R^-1 mod n = 1
 */
_Bool sb_test_mod_expt_p(void)
{
    const sb_fe_t two = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 2);
    const sb_fe_t thirtytwo = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 32);
    const sb_fe_t two_expt_thirtytwo = SB_FE_CONST_ALWAYS_QR(0, 0, 0,
                                                             0x100000000);
    sb_fe_t t, t2, t3;
    t = two;
    sb_fe_mod_expt(&t, &thirtytwo, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &two_expt_thirtytwo));

    t = SB_CURVE_P256_N.p;
    SB_FE_QR(&t, &SB_CURVE_P256_P);
    sb_fe_mod_expt(&t, &SB_CURVE_P256_P.p, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^p == n

    t = SB_CURVE_P256_N.p;
    SB_FE_QR(&t, &SB_CURVE_P256_P);
    sb_fe_mod_expt(&t, &SB_FE_ONE, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^1 = n

    t = SB_CURVE_P256_P.p;
    sb_fe_sub(&t, &t, &SB_FE_ONE);
    SB_FE_QR(&t, &SB_CURVE_P256_P);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    sb_fe_add(&t, &t, &SB_FE_ONE);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_P.p)); // (p-1)^-1 == (p-1)

    t = SB_FE_ONE;
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE)); // 1^-1 == 1

    // t = B * R^-1
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_P);

    // t = B^-1 * R
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);

    // t2 = B^-1 * R * B * R^-1 = 1
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t2, &SB_FE_ONE));

    // and again, mod N
    sb_fe_t b_n = SB_CURVE_P256.b;
    SB_FE_QR(&b_n, &SB_CURVE_P256_N);
    sb_fe_mont_mult(&t, &b_n, &SB_FE_ONE, &SB_CURVE_P256_N);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_N);
    sb_fe_mont_mult(&t2, &t, &b_n, &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t2, &SB_FE_ONE));
    return 1;
}

// Asserts that val has a square root x that mod_sqrt finds and x^2 = i
static _Bool sb_test_mod_sqrt_v(const sb_fe_t val[static const 1],
                                const sb_prime_field_t p[static const 1])
{
    sb_fe_t x, t1, t2, t3, t4;

    x = *val;
    SB_TEST_ASSERT(sb_fe_mod_sqrt(&x, &t1, &t2, &t3, &t4, p));

    sb_fe_mont_mult(&t1, val, &p->r2_mod_p, p);
    sb_fe_mont_mult(&t2, &x, &p->r2_mod_p, p);
    sb_fe_mont_square(&t3, &t2, p);
    SB_TEST_ASSERT(sb_fe_equal(&t1, &t3));

    return 1;
}

// Tests that mod_sqrt cannot find a square root for val. It is not
// necessarily the case that if mod_sqrt returns false the square root does
// not exist.
static _Bool sb_test_mod_sqrt_n(const sb_fe_t val[static const 1],
                                const sb_prime_field_t p[static const 1])
{
    sb_fe_t x, t1, t2, t3, t4;

    x = *val;
    SB_TEST_ASSERT(!sb_fe_mod_sqrt(&x, &t1, &t2, &t3, &t4, p));

    return 1;
}

// Tests that if mod_sqrt finds a square root x for val, that x^2 = i.
static _Bool sb_test_mod_sqrt_e(const sb_fe_t val[static const 1],
                                size_t valid_count[static const 1],
                                const sb_prime_field_t p[static const 1])
{
    sb_fe_t x, t1, t2, t3, t4;

    x = *val;
    if (sb_fe_mod_sqrt(&x, &t1, &t2, &t3, &t4, p)) {
        sb_fe_mont_mult(&t1, val, &p->r2_mod_p, p);
        sb_fe_mont_mult(&t2, &x, &p->r2_mod_p, p);
        sb_fe_mont_square(&t3, &t2, p);
        SB_TEST_ASSERT(sb_fe_equal(&t1, &t3));
        (*valid_count)++;
    }

    return 1;
}

/*
 * Tests that sqrt finds a square root for some number iff that number really
 * does have a square root (soundness).
 *
 * Operations tested:
 *  2, 32, and 2^32 have square roots in p256
 *  2, 32 and 2^32 have square roots in secp256k1
 *  3 does not have a square root in either p256 or secp256k1
 *  For values 0 =< i < 128, if a square root x is found then x^2 = i.
 *  There are 61 i values with a valid square root.
 */
_Bool sb_test_mod_sqrt(void)
{
    const sb_fe_t two = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 2);
    const sb_fe_t thirtytwo = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 32);
    const sb_fe_t two_expt_thirtytwo = SB_FE_CONST_ALWAYS_QR(0, 0, 0,
                                                             0x100000000);
    const sb_fe_t three = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 3);

    SB_TEST_ASSERT(sb_test_mod_sqrt_v(&two, &SB_CURVE_P256_P));
    SB_TEST_ASSERT(sb_test_mod_sqrt_v(&thirtytwo, &SB_CURVE_P256_P));
    SB_TEST_ASSERT(sb_test_mod_sqrt_v(&two_expt_thirtytwo, &SB_CURVE_P256_P));

    SB_TEST_ASSERT(sb_test_mod_sqrt_v(&two, &SB_CURVE_SECP256K1_P));
    SB_TEST_ASSERT(sb_test_mod_sqrt_v(&thirtytwo, &SB_CURVE_SECP256K1_P));
    SB_TEST_ASSERT(
        sb_test_mod_sqrt_v(&two_expt_thirtytwo, &SB_CURVE_SECP256K1_P));

    SB_TEST_ASSERT(sb_test_mod_sqrt_n(&three, &SB_CURVE_P256_P));
    SB_TEST_ASSERT(sb_test_mod_sqrt_n(&three, &SB_CURVE_P256_N));

    sb_fe_t x = SB_FE_ZERO;
    size_t vc = 0;
    for (size_t i = 0; i < 128; i++) {
        sb_fe_add(&x, &x, &SB_FE_ONE);
        SB_FE_QR(&x, &SB_CURVE_P256_P);
        SB_TEST_ASSERT(sb_test_mod_sqrt_e(&x, &vc, &SB_CURVE_P256_P));
    }

    SB_TEST_ASSERT(vc == 61);

    return 1;
}

#endif
