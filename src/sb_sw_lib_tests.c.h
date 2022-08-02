/** @file sb_sw_lib_tests.c.h
 *  @brief tests for operations on short Weierstrass elliptic curves
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is part of Sweet B, a safe, compact, embeddable library for
 * elliptic curve cryptography.
 *
 * https://github.com/westerndigitalcorporation/sweet-b
 *
 * Copyright (c) 2020-2021 Western Digital Corporation or its affiliates.
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

#ifdef SB_SW_LIB_TESTS_IMPL

static const sb_byte_t NULL_ENTROPY[32] = { 0 };

// Initialize a DRBG used for semi-randomized testing. Also sets the
// additional_input_required flag so that all curve operations can be checked
// for whether they provide additional input to the DRBG to ensure
// backtracking resistance.

#define NULL_DRBG_INIT(drbg) \
    do { \
        SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_init((drbg), NULL_ENTROPY, 32, \
            NULL_ENTROPY, 32, NULL, 0)); \
        (drbg)->additional_input_required = 1; \
    } while (0)

#define SB_TEST_RAND_COUNT 32

// De-incrementalized point multiplication wrapper for unit tests.
static void
sb_sw_point_mult(sb_sw_context_t m[static const 1],
                 const sb_sw_curve_t curve[static const 1])
{
    SB_NULLIFY(MULT_STATE(m));
    sb_sw_point_mult_start(m, curve);
    do {
    } while (!sb_sw_point_mult_continue(m, curve));
    sb_sw_point_mult_continue(m, curve);
}

/// Unit tests for internal routines:

// Test that computing 1 * P via the ladder produces P. Also tests -1 * P.
static _Bool test_ladder_unity(const sb_fe_pair_t point[static const 1],
                               const sb_sw_curve_t s[static const 1],
                               const _Bool invert)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));

    // k = 1
    *MULT_K(&m) = SB_FE_ONE;

    if (invert) {
        // k = -1
        sb_fe_mod_negate(MULT_K(&m), MULT_K(&m), s->n);
    }

    // z is any value, really
    *MULT_Z(&m) = s->p->r_mod_p;

    *MULT_POINT(&m) = *point;

    sb_sw_point_mult(&m, s);
    // produces P in X1 and Y1

    // convert (X1, Y1) back into the Montgomery domain for comparison
    sb_fe_mont_mult(C_X2(&m), C_X1(&m), &s->p->r2_mod_p,
                    s->p);
    sb_fe_mont_mult(C_Y2(&m), C_Y1(&m), &s->p->r2_mod_p,
                    s->p);

    if (invert) {
        // invert the result for comparison
        sb_fe_mod_negate(C_Y2(&m), C_Y2(&m), s->p);
    }

    SB_TEST_ASSERT(sb_fe_equal(&point->x, C_X2(&m)));
    SB_TEST_ASSERT(sb_fe_equal(&point->y, C_Y2(&m)));

    return 1;
}

// Test that computing 2 * P via the ladder produces the same result as
// sb_sw_point_initial_double. Also tests -2 * P.
static _Bool test_ladder_double(const sb_fe_pair_t point[static const 1],
                                const sb_sw_curve_t s[static const 1],
                                const _Bool invert)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));

    // Set up our initial point, which is assumed to be pre-multiplied by R
    *MULT_POINT_X(&m) = point->x;
    *MULT_POINT_Y(&m) = point->y;

    // k = 2
    const sb_fe_t two = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 2);
    *MULT_K(&m) = two;

    if (invert) {
        // k = -2
        sb_fe_mod_negate(MULT_K(&m), MULT_K(&m), s->n);
    }

    // z is any value, really
    *MULT_Z(&m) = s->p->r_mod_p;

    sb_sw_point_mult(&m, s);
    // produces 2 * P in X1 and Y1

    // save 2 * P with values multiplied by R for later comparison
    sb_fe_mont_mult(MULT_POINT_X(&m), C_X1(&m), &s->p->r2_mod_p,
                    s->p);
    sb_fe_mont_mult(MULT_POINT_Y(&m), C_Y1(&m), &s->p->r2_mod_p,
                    s->p);

    *C_X2(&m) = point->x;
    *C_Y2(&m) = point->y;
    sb_sw_point_initial_double(&m, s);
    // produces 2 * P in X2 and Y2, with some Z in t5

    // apply that Z to the initial point
    sb_fe_mont_square(C_T6(&m), C_T5(&m), s->p); // z^2
    sb_fe_mont_mult(C_T7(&m), C_T5(&m), C_T6(&m), s->p); // z^3

    sb_fe_mont_mult(C_X1(&m), MULT_POINT_X(&m), C_T6(&m), s->p); // x * z^2
    sb_fe_mont_mult(C_Y1(&m), MULT_POINT_Y(&m), C_T7(&m), s->p); // y * z^3

    if (invert) {
        // invert the result of sb_sw_point_initial_double for comparison
        sb_fe_mod_negate(C_Y2(&m), C_Y2(&m), s->p);
    }

    SB_TEST_ASSERT(sb_fe_equal(C_X1(&m), C_X2(&m)));
    SB_TEST_ASSERT(sb_fe_equal(C_Y1(&m), C_Y2(&m)));

    return 1;
}

// Test driver for the unity and doubling tests
static _Bool test_ladder_simple(const sb_fe_pair_t point[static const 1],
                                const sb_sw_curve_t s[static const 1])
{
    SB_TEST_ASSERT(test_ladder_unity(point, s, 0));
    SB_TEST_ASSERT(test_ladder_unity(point, s, 1));
    SB_TEST_ASSERT(test_ladder_double(point, s, 0));
    SB_TEST_ASSERT(test_ladder_double(point, s, 1));
    return 1;
}

// Test the simple scalars of 1, 2, -1, and -2.
_Bool sb_test_ladder_simple(void)
{
    SB_TEST_ASSERT(test_ladder_simple(&SB_CURVE_P256.g_r, &SB_CURVE_P256));
    SB_TEST_ASSERT(test_ladder_simple(&SB_CURVE_P256.h_r, &SB_CURVE_P256));
    SB_TEST_ASSERT(test_ladder_simple(&SB_CURVE_P256.g_h_r, &SB_CURVE_P256));

    // Testing for (0, sqrt(B))
    for (sb_word_t sign = 0; sign <= 1; sign++) {
        const sb_sw_curve_t* const s = &SB_CURVE_P256;
        sb_sw_context_t m;
        SB_NULLIFY(&m); // entire structure is now zeroed

        SB_TEST_ASSERT(sb_sw_point_decompress(&m, sign, s));
        // MULT_POINT(&m) now holds (0, sqrt(B))

        sb_double_t z;
        SB_NULLIFY(&z);
        sb_fe_to_bytes(z.bytes + SB_ELEM_BYTES, MULT_POINT_Y(&m), SB_DATA_ENDIAN_BIG);
        // z now holds (0, sqrt(B)) as a serialized point

        sb_fe_pair_t zp;

        zp.x = s->p->p;
        sb_fe_mont_convert(&zp.y, &MULT_POINT(&m)->y, s->p);

        SB_TEST_ASSERT(test_ladder_simple(&zp, &SB_CURVE_P256));
    }

    SB_TEST_ASSERT(
        test_ladder_simple(&SB_CURVE_SECP256K1.g_r, &SB_CURVE_SECP256K1));
    SB_TEST_ASSERT(
        test_ladder_simple(&SB_CURVE_SECP256K1.h_r, &SB_CURVE_SECP256K1));
    SB_TEST_ASSERT(
        test_ladder_simple(&SB_CURVE_SECP256K1.g_h_r, &SB_CURVE_SECP256K1));
    return 1;
}

// A helper to verify the order of an element of the given prime field.
static _Bool verify_order(const sb_fe_t e[static const 1],
                          const size_t order,
                          const sb_prime_field_t p[static const 1])
{
    sb_fe_t e_r;
    sb_fe_mont_mult(&e_r, e, &p->r2_mod_p, p);

    sb_fe_t v = e_r, v2;
    for (size_t i = 0; i < order; i++) {
        sb_fe_mont_mult(&v2, &v, &e_r, p);
        if (i == order - 1) {
            SB_TEST_ASSERT(sb_fe_equal(&v2, &e_r));
        } else if (i == order - 2) {
            SB_TEST_ASSERT(sb_fe_equal(&v2, &p->r_mod_p));
        } else {
            SB_TEST_ASSERT(!sb_fe_equal(&v2, &e_r));
        }
        v = v2;
    }
    return 1;
}

// Test the endomorphism of the secp256k1 curve by verifying that the
// identity lambda * (X, Y) = (beta * X, Y) holds, and that our prime field
// arithmetic behaves as expected given the order of lambda and beta
_Bool sb_test_secp256k1_endomorphism(void)
{
    static const sb_fe_t lambda =
        SB_FE_CONST_QR(0x5363AD4CC05C30E0, 0xA5261C028812645A,
                       0x122E22EA20816678, 0xDF02967C1B23BD72,
                       &SB_CURVE_SECP256K1_N);
    static const sb_fe_t beta =
        SB_FE_CONST_QR(0x7AE96A2B657C0710, 0x6E64479EAC3434E9,
                       0x9CF0497512F58995, 0xC1396C28719501EE,
                       &SB_CURVE_SECP256K1_P);
    sb_sw_context_t ct;
    memset(&ct, 0, sizeof(ct));

    SB_TEST_ASSERT(verify_order(&lambda, 3, &SB_CURVE_SECP256K1_N));
    SB_TEST_ASSERT(verify_order(&beta, 3, &SB_CURVE_SECP256K1_P));

    sb_fe_t x, y, beta_r;

    *MULT_Z(&ct) = SB_CURVE_SECP256K1_P.r_mod_p;
    *MULT_K(&ct) = lambda;
    *MULT_POINT_X(&ct) = SB_CURVE_SECP256K1.g_r.x;
    *MULT_POINT_Y(&ct) = SB_CURVE_SECP256K1.g_r.y;

    sb_fe_mont_reduce(&x, MULT_POINT_X(&ct), SB_CURVE_SECP256K1.p);
    sb_fe_mont_reduce(&y, MULT_POINT_Y(&ct), SB_CURVE_SECP256K1.p);
    sb_fe_mont_mult(&beta_r, &beta, &SB_CURVE_SECP256K1_P.r2_mod_p,
                    &SB_CURVE_SECP256K1_P);

    /* lambda has order 3 mod n. thus, (lambda^3) * G = G. */
    for (size_t i = 0; i < 3; i++) {
        sb_sw_point_mult(&ct, &SB_CURVE_SECP256K1);

        SB_TEST_ASSERT(sb_fe_equal(&lambda, MULT_K(&ct)));
        sb_fe_mont_mult(C_T5(&ct), &x, &beta_r, &SB_CURVE_SECP256K1_P);
        x = *C_T5(&ct);
        SB_TEST_ASSERT(sb_fe_equal(&x, C_X1(&ct)));
        SB_TEST_ASSERT(sb_fe_equal(&y, C_Y1(&ct)));

        sb_fe_mont_mult(MULT_POINT_X(&ct), C_X1(&ct),
                        &SB_CURVE_SECP256K1_P.r2_mod_p, &SB_CURVE_SECP256K1_P);
        sb_fe_mont_mult(MULT_POINT_Y(&ct), C_Y1(&ct),
                        &SB_CURVE_SECP256K1_P.r2_mod_p, &SB_CURVE_SECP256K1_P);

        if (i == 2) {
            SB_TEST_ASSERT(sb_fe_equal(MULT_POINT_X(&ct),
                                       &SB_CURVE_SECP256K1.g_r.x));
        } else {
            SB_TEST_ASSERT(!sb_fe_equal(MULT_POINT_X(&ct),
                                        &SB_CURVE_SECP256K1.g_r.y));
        }
        SB_TEST_ASSERT(sb_fe_equal(MULT_POINT_Y(&ct),
                                   &SB_CURVE_SECP256K1.g_r.y));
    }
    return 1;
}

// The following scalars would cause exceptions in the ladder.
// Test that our handling of these exceptions is valid.
_Bool sb_test_exceptions(void)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));
    *MULT_Z(&m) = SB_FE_ONE;

    // Exceptions produce P, not zero, due to ZVA countermeasures
#define EX_ZERO(c) ((c).p->p)

#define TEST_EX(kv, pv) do { \
    *MULT_K(&m) = (kv); \
    *MULT_POINT(&m) = (pv); \
    SB_TEST_ASSERT(!sb_sw_scalar_validate(MULT_K(&m), &SB_CURVE_P256)); \
    sb_sw_point_mult(&m, &SB_CURVE_P256); \
    SB_TEST_ASSERT(sb_fe_equal(C_X1(&m), &EX_ZERO(SB_CURVE_P256)) && \
           sb_fe_equal(C_Y1(&m), &EX_ZERO(SB_CURVE_P256))); \
} while (0)

#define TEST_NO_EX(kv, pv) do { \
    *MULT_K(&m) = (kv); \
    *MULT_POINT(&m) = (pv); \
    SB_TEST_ASSERT(sb_sw_scalar_validate(MULT_K(&m), &SB_CURVE_P256)); \
    sb_sw_point_mult(&m, &SB_CURVE_P256); \
    SB_TEST_ASSERT(!(sb_fe_equal(C_X1(&m), &EX_ZERO(SB_CURVE_P256)) && \
           sb_fe_equal(C_Y1(&m), &EX_ZERO(SB_CURVE_P256)))); \
} while (0)

    sb_fe_t k;
    const sb_fe_pair_t g = SB_CURVE_P256.g_r;

    sb_fe_pair_t z_even, z_odd;

    z_even.x = SB_CURVE_P256_P.p;
    z_odd.x = SB_CURVE_P256_P.p;

    *MULT_POINT_X(&m) = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_sw_point_decompress(&m, 0, &SB_CURVE_P256));
    sb_fe_mont_convert(&z_even.y, MULT_POINT_Y(&m), &SB_CURVE_P256_P);

    *MULT_POINT_X(&m) = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_sw_point_decompress(&m, 1, &SB_CURVE_P256));
    sb_fe_mont_convert(&z_odd.y, MULT_POINT_Y(&m), &SB_CURVE_P256_P);

    // This is not an exception, strictly speaking.
    // k = 0
    TEST_EX(SB_CURVE_P256.n->p, g);
    TEST_EX(SB_CURVE_P256.n->p, z_even);
    TEST_EX(SB_CURVE_P256.n->p, z_odd);

    // k = 1
    TEST_NO_EX(SB_FE_ONE, g);
    TEST_NO_EX(SB_FE_ONE, z_even);
    TEST_NO_EX(SB_FE_ONE, z_odd);

    // k = -1
    k = SB_CURVE_P256.n->p;
    sb_fe_mod_sub(&k, &k, &SB_FE_ONE, SB_CURVE_P256.n);
    TEST_NO_EX(k, g);
    TEST_NO_EX(k, z_even);
    TEST_NO_EX(k, z_odd);

    // k = -2
    k = SB_CURVE_P256.n->p;
    sb_fe_mod_sub(&k, &k, &SB_FE_ONE, SB_CURVE_P256.n);
    sb_fe_mod_double(&k, &k, SB_CURVE_P256.n);
    TEST_NO_EX(k, g);
    TEST_NO_EX(k, z_even);
    TEST_NO_EX(k, z_odd);

    // k = 2
    k = SB_FE_ONE;
    sb_fe_mod_double(&k, &k, SB_CURVE_P256.n);
    TEST_NO_EX(k, g);
    TEST_NO_EX(k, z_even);
    TEST_NO_EX(k, z_odd);

    // k = -4 causes exceptions for (0, ±√B)
    k = SB_CURVE_P256.n->p;
    sb_fe_mod_sub(&k, &k, &SB_FE_ONE, SB_CURVE_P256.n);
    sb_fe_mod_double(&k, &k, SB_CURVE_P256.n);
    sb_fe_mod_double(&k, &k, SB_CURVE_P256.n);
    TEST_NO_EX(k, g);
    TEST_NO_EX(k, z_even);
    TEST_NO_EX(k, z_odd);

    // k = 4 causes exceptions for (0, ±√B)
    k = SB_FE_ONE;
    sb_fe_mod_double(&k, &k, SB_CURVE_P256.n);
    sb_fe_mod_double(&k, &k, SB_CURVE_P256.n);
    TEST_NO_EX(k, g);
    TEST_NO_EX(k, z_even);
    TEST_NO_EX(k, z_odd);

    return 1;
}

// Test that the "h" value used in the multiplication-addition routine is
// defined correctly.
static _Bool test_h(const sb_sw_curve_t* s)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));
    *MULT_Z(&m) = SB_FE_ONE;
    *MULT_K(&m) = (sb_fe_t) SB_FE_CONST(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
    sb_fe_sub(MULT_K(&m), MULT_K(&m), &s->n->p);
    sb_fe_sub(MULT_K(&m), MULT_K(&m), &s->n->p);
    SB_FE_QR(MULT_K(&m), s->n);
    const sb_fe_t h_inv = *MULT_K(&m);
    sb_fe_mont_mult(C_T5(&m), MULT_K(&m), &s->n->r2_mod_p,
                    s->n);
    sb_fe_mod_inv_r(C_T5(&m), C_T6(&m), C_T7(&m), s->n);
    sb_fe_mont_mult(MULT_K(&m), C_T5(&m), &SB_FE_ONE, s->n);
    *MULT_POINT(&m) = s->g_r;
    sb_sw_point_mult(&m, s);

    sb_fe_mont_mult(MULT_POINT_X(&m), C_X1(&m), &s->p->r2_mod_p, s->p);
    sb_fe_mont_mult(MULT_POINT_Y(&m), C_Y1(&m), &s->p->r2_mod_p, s->p);

    SB_TEST_ASSERT(sb_fe_equal(MULT_POINT_X(&m), &s->h_r.x));
    SB_TEST_ASSERT(sb_fe_equal(MULT_POINT_Y(&m), &s->h_r.y));


    *MULT_K(&m) = h_inv;
    sb_sw_point_mult(&m, s);
    sb_fe_mont_mult(C_X2(&m), &s->g_r.x, &SB_FE_ONE, s->p);
    sb_fe_mont_mult(C_Y2(&m), &s->g_r.y, &SB_FE_ONE, s->p);
    SB_TEST_ASSERT(sb_fe_equal(C_X1(&m), C_X2(&m)));
    SB_TEST_ASSERT(sb_fe_equal(C_Y1(&m), C_Y2(&m)));

    return 1;
}

// Use test_h to test the "h" value for both curves.
_Bool sb_test_sw_h(void)
{
    SB_TEST_ASSERT(test_h(&SB_CURVE_P256));
    SB_TEST_ASSERT(test_h(&SB_CURVE_SECP256K1));

    return 1;
}

// Test that the special value dz_r is computed correctly.
_Bool sb_test_p256_dz(void)
{
    const sb_sw_curve_t* const s = &SB_CURVE_P256;
    sb_sw_context_t m;
    SB_NULLIFY(&m); // entire structure is now zeroed

    SB_TEST_ASSERT(sb_sw_point_decompress(&m, 0, s));
    // MULT_POINT(&m) now holds (0, sqrt(B))

    sb_double_t z;
    SB_NULLIFY(&z);
    sb_fe_to_bytes(z.bytes + SB_ELEM_BYTES, MULT_POINT_Y(&m), SB_DATA_ENDIAN_BIG);
    // z now holds (0, sqrt(B)) as a serialized point

    *C_X2(&m) = s->p->p;
    sb_fe_mont_convert(C_Y2(&m), &MULT_POINT(&m)->y, s->p);

    sb_sw_point_initial_double(&m, s);
    // (x2, y2) now holds 2*P with Z in t5

    sb_fe_mod_inv_r(C_T5(&m), C_T6(&m), C_T7(&m), s->p);
    // t5 now holds Z^-1

    sb_fe_mont_square(C_T6(&m), C_T5(&m), s->p); // t6 = Z^-2
    sb_fe_mont_mult(C_T7(&m), C_T5(&m), C_T6(&m), s->p); // t7 = Z^-3

    sb_fe_mont_mult(C_X1(&m), C_X2(&m), C_T6(&m), s->p); // x1 = x2 * Z^-2
    sb_fe_mont_mult(C_Y1(&m), C_Y2(&m), C_T7(&m), s->p); // y1 = y2 * Z^-3

    // Verify dz_r
    SB_TEST_ASSERT_EQUAL(*C_X1(&m), s->dz_r.x);
    SB_TEST_ASSERT_EQUAL(*C_Y1(&m), s->dz_r.y);

    // Montgomery reduce to obtain output point
    sb_fe_mont_reduce(MULT_POINT_X(&m), C_X1(&m), s->p);
    sb_fe_mont_reduce(MULT_POINT_Y(&m), C_Y1(&m), s->p);

    sb_double_t p;
    sb_fe_to_bytes(p.bytes, MULT_POINT_X(&m), SB_DATA_ENDIAN_BIG);
    sb_fe_to_bytes(p.bytes + SB_ELEM_BYTES, MULT_POINT_Y(&m), SB_DATA_ENDIAN_BIG);

    // p now holds 2 * (0, sqrt(B))

    sb_single_t k, k_inv;
    // t5 = 2
    *C_T5(&m) = (sb_fe_t) SB_FE_CONST_QR(0, 0, 0, 2, &SB_CURVE_P256_P);
    sb_fe_to_bytes(k.bytes, C_T5(&m), SB_DATA_ENDIAN_BIG);

    SB_TEST_ASSERT_SUCCESS(sb_sw_invert_private_key(&m, &k_inv, &k, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));

    // k_inv = 2^-1 mod p

    sb_double_t o;

    SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&m, &o, &k_inv, &p, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(o, z);

    return 1;
}

// Wrapper for the Shamir's trick function to extract only the functionality
// without the signature verification details.
static void sb_sw_point_mult_add_z(sb_sw_context_t q[static const 1],
                                   const sb_sw_curve_t s[static const 1])
{
    *MULT_STATE(q) = (sb_sw_context_saved_state_t) {
        .operation = SB_SW_INCREMENTAL_OPERATION_VERIFY_SIGNATURE,
        .stage = SB_SW_VERIFY_OP_STAGE_INV_Z
    };
    while (!sb_sw_point_mult_add_z_continue(q, s));
}

// Test that A * (B * G) + C * G = (A * B + C) * G
static _Bool test_sw_point_mult_add(const sb_fe_t* const ka,
                                    const sb_fe_t* const kb,
                                    const sb_fe_t* const kc,
                                    const sb_sw_curve_t* const s)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));

    sb_fe_t kabc;

    sb_fe_mont_mult(C_T5(&m), ka, kb, s->n);
    sb_fe_mont_mult(&kabc, C_T5(&m), &s->n->r2_mod_p, s->n);
    sb_fe_mod_add(&kabc, &kabc, kc, s->n);

    *MULT_Z(&m) = SB_FE_ONE;

    *MULT_K(&m) = *kb;

    *MULT_POINT(&m) = s->g_r;
    sb_sw_point_mult(&m, s);

    sb_fe_pair_t pb = { *C_X1(&m), *C_Y1(&m) };

    *MULT_K(&m) = kabc;
    *MULT_POINT(&m) = s->g_r;
    sb_sw_point_mult(&m, s);

    sb_fe_pair_t pabc = { *C_X1(&m), *C_Y1(&m) };

    sb_sw_context_t q;
    memset(&q, 0, sizeof(q));
    *MULT_Z(&q) = SB_FE_ONE;

    *MULT_POINT_X(&q) = pb.x;
    *MULT_POINT_Y(&q) = pb.y;
    *MULT_K(&q) = *ka;
    *MULT_ADD_KG(&q) = *kc;

    // A * (B * G) + C * G = (A * B + C) * G
    sb_sw_point_mult_add_z(&q, s);

    // put pabc in co-Z with the result
    sb_fe_mont_square(C_T6(&q), MULT_Z(&q), s->p); // t6 = Z^2 * R
    sb_fe_mont_mult(C_T7(&q), C_T6(&q), MULT_Z(&q), s->p); // t7 = Z^3 * R

    sb_fe_mont_mult(C_X2(&q), C_T6(&q), &pabc.x, s->p); // x2 = x * Z^2
    sb_fe_mont_mult(C_Y2(&q), C_T7(&q), &pabc.y, s->p); // y2 = y * Z^3
    SB_TEST_ASSERT(
        sb_fe_equal(C_X1(&q), C_X2(&q)) & sb_fe_equal(C_Y1(&q), C_Y2(&q)));
    return 1;
}

// Generate a completely random fe value using the given drbg
static _Bool generate_fe(sb_fe_t* const fe, sb_hmac_drbg_state_t* const drbg)
{
    sb_single_t s;
    SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_generate_additional_dummy
                               (drbg, s.bytes, SB_ELEM_BYTES));
    sb_fe_from_bytes(fe, s.bytes, SB_DATA_ENDIAN_BIG);
    return 1;
}

// A simple test of the Shamir's trick dual scalar-point
// multiplication-addition routine using the test_sw_point_mult_add helper
// defined above.
_Bool sb_test_sw_point_mult_add(void)
{
    sb_fe_t ka = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 3);
    sb_fe_t kb = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 4);
    sb_fe_t kc = SB_FE_CONST_ALWAYS_QR(0, 0, 0, 6);
    SB_TEST_ASSERT(test_sw_point_mult_add(&ka, &kb, &kc, &SB_CURVE_P256));
    SB_TEST_ASSERT(test_sw_point_mult_add(&ka, &kb, &kc, &SB_CURVE_SECP256K1));
    return 1;
}

/// Unit tests of external APIs:

// Test using HKDF to expand a private key by verifying that the same inputs
// always generate the same private key.
static _Bool sb_test_hkdf_expand_private(const sb_sw_curve_id_t c,
                                         const sb_data_endian_t e)
{
    static const sb_byte_t salt[] = "salty";
    static const sb_byte_t input[] = "need input";

    static const sb_byte_t info1[] = "info1";
    static const sb_byte_t info2[] = "info2";

    sb_sw_context_t ctx;
    sb_hkdf_state_t hkdf;
    sb_sw_private_t private1, private2;
    sb_sw_public_t public1, public2;

    sb_hkdf_extract(&hkdf, salt, sizeof(salt) - 1, input, sizeof(input) - 1);

    // First test: different info labels generate different keys.
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_hkdf_expand_private_key(&ctx, &private1, &hkdf, info1,
                                      sizeof(info1) - 1, c, e));
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_hkdf_expand_private_key(&ctx, &private2, &hkdf, info2,
                                      sizeof(info2) - 1, c, e));

    SB_TEST_ASSERT_NOT_EQUAL(private1, private2);

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_compute_public_key(&ctx, &public1, &private1, NULL, c, e));

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_compute_public_key(&ctx, &public2, &private2, NULL, c, e));

    SB_TEST_ASSERT_NOT_EQUAL(public1, public2);


    // Second test: same info label generates the same key.
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_hkdf_expand_private_key(&ctx, &private2, &hkdf, info1,
                                      sizeof(info1) - 1, c, e));
    SB_TEST_ASSERT_EQUAL(private1, private2);


    SB_TEST_ASSERT_SUCCESS(
        sb_sw_compute_public_key(&ctx, &public2, &private2, NULL, c, e));
    SB_TEST_ASSERT_EQUAL(public1, public2);


    // Third test: doing the extract again doesn't affect the result.
    memset(&hkdf, 0, sizeof(hkdf));
    sb_hkdf_extract(&hkdf, salt, sizeof(salt) - 1, input, sizeof(input) - 1);

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_hkdf_expand_private_key(&ctx, &private2, &hkdf, info1,
                                      sizeof(info1) - 1, c, e));
    SB_TEST_ASSERT_EQUAL(private1, private2);


    SB_TEST_ASSERT_SUCCESS(
        sb_sw_compute_public_key(&ctx, &public2, &private2, NULL, c, e));
    SB_TEST_ASSERT_EQUAL(public1, public2);

    return 1;
}

// Test HKDF private key generation for P-256
_Bool sb_test_hkdf_expand_private_p256(void)
{
    return sb_test_hkdf_expand_private(SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);
}

// Test HKDF private key generation for secp256k1
_Bool sb_test_hkdf_expand_private_secp256k1(void)
{
    return sb_test_hkdf_expand_private(SB_SW_CURVE_SECP256K1,
                                       SB_DATA_ENDIAN_LITTLE);
}

// Generated private key.
static const sb_sw_private_t TEST_PRIV_1 = {
    {
        0x5E, 0x7F, 0x68, 0x59, 0x05, 0xE6, 0xB8, 0x08,
        0xAE, 0xF8, 0xE9, 0x2D, 0x59, 0x6F, 0xAC, 0x9B,
        0xC5, 0x33, 0x6C, 0x2B, 0xB8, 0x11, 0x3C, 0x87,
        0x7E, 0x7E, 0x5B, 0xBD, 0xB1, 0x4E, 0x83, 0x74
    }};

// is NOT the public key for TEST_PRIV_1. It's just some
// valid public key.
static const sb_sw_public_t TEST_PUB_1 = {
    {
        0xA7, 0xE2, 0x9A, 0x43, 0x86, 0x95, 0xCF, 0xD0,
        0x0A, 0x0A, 0xCB, 0x0D, 0x86, 0x1C, 0x6C, 0xA5,
        0x99, 0xF8, 0xB5, 0xC4, 0x93, 0xC9, 0xA2, 0x78,
        0xBA, 0x85, 0xDD, 0x46, 0x45, 0x03, 0xD7, 0x2D,
        0x0D, 0x76, 0xCE, 0xD9, 0xFE, 0x9F, 0x7F, 0x92,
        0x05, 0x05, 0x84, 0xEC, 0x58, 0x0D, 0x57, 0x51,
        0x29, 0xA9, 0xB4, 0x21, 0x54, 0x15, 0x0A, 0x04,
        0x45, 0x89, 0xBE, 0x2A, 0x25, 0xC2, 0xB0, 0x6D
    }
};

// Sample private scalar from RFC 6979 p.32
static const sb_sw_private_t TEST_PRIV_2 = {
    {
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16,
        0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
        0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
        0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
    }
};

// The public key for TEST_PRIV_2. Also defined in RFC 6979 p.32
static const sb_sw_public_t TEST_PUB_2 = {
    {
        0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
        0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
        0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
        0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
        0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
        0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99
    }
};

// A simple unit test of the public-key generation routine.
_Bool sb_test_compute_public(void)
{
    sb_sw_public_t pub;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_compute_public_key(&ct, &pub, &TEST_PRIV_2, NULL,
                                 SB_SW_CURVE_P256,
                                 SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(pub, TEST_PUB_2);
    return 1;
}

// A simple unit test of the private-key validation routine.
_Bool sb_test_valid_private(void)
{
    sb_sw_context_t ct;

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_private_key(&ct, &TEST_PRIV_1, SB_SW_CURVE_P256,
                                SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_private_key(&ct, &TEST_PRIV_1, SB_SW_CURVE_P256,
                                SB_DATA_ENDIAN_BIG));

    static const sb_sw_private_t invalid_priv = {
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        }
    };

    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_private_key(&ct, &invalid_priv, SB_SW_CURVE_P256,
                                SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_private_key(&ct, &invalid_priv, SB_SW_CURVE_P256,
                                SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_private_key(&ct, &invalid_priv, SB_SW_CURVE_SECP256K1,
                                SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_private_key(&ct, &invalid_priv, SB_SW_CURVE_SECP256K1,
                                SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    return 1;
}

// A simple unit test of the public-key validation routine.
_Bool sb_test_valid_public(void)
{
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_public_key(&ct, &TEST_PUB_1, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_public_key(&ct, &TEST_PUB_2, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_public_key(&ct, &TEST_PUB_2, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PUBLIC_KEY_INVALID);
    return 1;
}

// A basic unit test of the shared secret routine, where
// TEST_PRIV_1 is entity i's private key, TEST_PUB_1 is
// entity j's public key, and secret is the known correct
// shared secret.
_Bool sb_test_shared_secret(void)
{
    static const sb_sw_private_t secret = {
        {
            0xB5, 0xF9, 0x02, 0x52, 0xB8, 0xCA, 0xF8, 0x46,
            0x3B, 0x8B, 0x73, 0x77, 0x48, 0x32, 0x3B, 0x89,
            0xD2, 0x54, 0x35, 0x88, 0xE1, 0x29, 0xDF, 0x6E,
            0x33, 0xE1, 0x68, 0xEC, 0x31, 0x72, 0x19, 0x22
        }
    };

    sb_sw_shared_secret_t out;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_shared_secret(&ct, &out, &TEST_PRIV_1, &TEST_PUB_1, NULL,
                            SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(out, secret);
    return 1;
}

// Another basic unit test extracted from the CAVP example vectors.
// Tests both compute_public_key and shared_secret, which do the
// same thing.
_Bool sb_test_shared_secret_cavp_1(void)
{
    static const sb_sw_public_t pub1 = {
        {
            0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c,
            0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
            0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4,
            0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
            0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06,
            0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
            0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0,
            0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
        }
    };

    static const sb_sw_private_t priv2 = {
        {
            0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda,
            0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
            0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e,
            0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
        }
    };

    static const sb_sw_public_t pub2 = {
        {
            0xea, 0xd2, 0x18, 0x59, 0x01, 0x19, 0xe8, 0x87,
            0x6b, 0x29, 0x14, 0x6f, 0xf8, 0x9c, 0xa6, 0x17,
            0x70, 0xc4, 0xed, 0xbb, 0xf9, 0x7d, 0x38, 0xce,
            0x38, 0x5e, 0xd2, 0x81, 0xd8, 0xa6, 0xb2, 0x30,
            0x28, 0xaf, 0x61, 0x28, 0x1f, 0xd3, 0x5e, 0x2f,
            0xa7, 0x00, 0x25, 0x23, 0xac, 0xc8, 0x5a, 0x42,
            0x9c, 0xb0, 0x6e, 0xe6, 0x64, 0x83, 0x25, 0x38,
            0x9f, 0x59, 0xed, 0xfc, 0xe1, 0x40, 0x51, 0x41
        }
    };

    static const sb_sw_shared_secret_t secret = {
        {
            0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01,
            0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
            0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68,
            0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b
        }
    };

    sb_sw_context_t ct;
    sb_sw_shared_secret_t out;
    sb_sw_public_t c_pub2;
    SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &c_pub2, &priv2, NULL,
                                                    SB_SW_CURVE_P256,
                                                    SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(c_pub2, pub2);
    SB_TEST_ASSERT_SUCCESS(sb_sw_shared_secret(&ct, &out, &priv2, &pub1, NULL,
                                               SB_SW_CURVE_P256,
                                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(out, secret);
    return 1;
}

_Bool sb_test_compressed_pub_shared_secret(void) {
    const sb_sw_compressed_t wycheproof_compressed = {
        {
            0x62, 0xd5, 0xbd, 0x33, 0x72, 0xaf, 0x75, 0xfe, 
            0x85, 0xa0, 0x40, 0x71, 0x5d, 0x0f, 0x50, 0x24, 
            0x28, 0xe0, 0x70, 0x46, 0x86, 0x8b, 0x0b, 0xfd, 
            0xfa, 0x61, 0xd7, 0x31, 0xaf, 0xe4, 0x4f, 0x26
        }
    };

    const sb_sw_private_t wycheproof_private = {
        {
            0x06, 0x12, 0x46, 0x5c, 0x89, 0xa0, 0x23, 0xab,
            0x17, 0x85, 0x5b, 0x0a, 0x6b, 0xce, 0xbf, 0xd3, 
            0xfe, 0xbb, 0x53, 0xae, 0xf8, 0x41, 0x38, 0x64, 
            0x7b, 0x53, 0x52, 0xe0, 0x2c, 0x10, 0xc3, 0x46
        }
    };

    const sb_sw_shared_secret_t wycheproof_shared = {
        {
            0x53, 0x02, 0x0d, 0x90, 0x8b, 0x02, 0x19, 0x32, 
            0x8b, 0x65, 0x8b, 0x52, 0x5f, 0x26, 0x78, 0x0e, 
            0x3a, 0xe1, 0x2b, 0xcd, 0x95, 0x2b, 0xb2, 0x5a, 
            0x93, 0xbc, 0x08, 0x95, 0xe1, 0x71, 0x42, 0x85
        }
    };

    sb_sw_context_t ct;
    sb_sw_shared_secret_t out;
    sb_sw_public_t pub;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_decompress_public_key(&ct, &pub, &wycheproof_compressed, 0, 
                                    SB_SW_CURVE_P256,
                                    SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_shared_secret(&ct, &out, &wycheproof_private, &pub, NULL,
                            SB_SW_CURVE_P256,
                            SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(out, wycheproof_shared);
    return 1;

}

_Bool sb_test_compressed_pub_verify(void) 
{
    const sb_sw_compressed_t wycheproof_compressed = {
        {
            0x29, 0x27, 0xb1, 0x05, 0x12, 0xba, 0xe3, 0xed, 
            0xdc, 0xfe, 0x46, 0x78, 0x28, 0x12, 0x8b, 0xad, 
            0x29, 0x03, 0x26, 0x99, 0x19, 0xf7, 0x08, 0x60, 
            0x69, 0xc8, 0xc4, 0xdf, 0x6c, 0x73, 0x28, 0x38
        }
    };

    const sb_sw_signature_t  wycheproof_signature = {
        {
            0x2b, 0xa3, 0xa8, 0xbe, 0x6b, 0x94, 0xd5, 0xec, 
            0x80, 0xa6, 0xd9, 0xd1, 0x19, 0x0a, 0x43, 0x6e, 
            0xff, 0xe5, 0x0d, 0x85, 0xa1, 0xee, 0xe8, 0x59, 
            0xb8, 0xcc, 0x6a, 0xf9, 0xbd, 0x5c, 0x2e, 0x18, 
            0xb3, 0x29, 0xf4, 0x79, 0xa2, 0xbb, 0xd0, 0xa5, 
            0xc3, 0x84, 0xee, 0x14, 0x93, 0xb1, 0xf5, 0x18, 
            0x6a, 0x87, 0x13, 0x9c, 0xac, 0x5d, 0xf4, 0x08, 
            0x7c, 0x13, 0x4b, 0x49, 0x15, 0x68, 0x47, 0xdb
        }
    };

    const sb_byte_t wycheproof_message[] = {
        0x31, 0x32, 0x33, 0x34, 0x30, 0x30
    };

    const size_t wycheproof_message_size = 6;

    sb_sw_context_t ct;
    sb_sw_public_t pub, bad_pub;
    sb_sw_message_digest_t digest;

    sb_hmac_drbg_state_t drbg;
    
    NULL_DRBG_INIT(&drbg);

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_decompress_public_key(&ct, &pub, &wycheproof_compressed, 0, 
                                    SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    
    // Decompress with the wrong sign bit also to ensure that using this
    // public key fails the verification
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_decompress_public_key(&ct, &bad_pub, &wycheproof_compressed, 1, 
                                    SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));

    // This signature should verify correctly.
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_verify_signature_sha256(&ct, &digest, &wycheproof_signature, 
                                      &pub, wycheproof_message, 
                                      wycheproof_message_size, &drbg, 
                                      SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    
    // This verification using the public key decompressed with the wrong 
    // sign bit should fail.
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature_sha256(&ct, &digest, &wycheproof_signature, 
                                      &bad_pub, wycheproof_message, 
                                      wycheproof_message_size, &drbg, 
                                      SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG)
    , SB_ERROR_SIGNATURE_INVALID);

    return 1;

}

// Test that the point (0, ±√𝐵) is handled correctly in shared secrets.
_Bool sb_test_p256_zero_x(void)
{
    sb_sw_context_t ct;

    const sb_sw_compressed_t zero = { .bytes = { 0 } };

    sb_sw_public_t p_zero;
    sb_sw_public_t p_zero_pos;

    sb_sw_public_t sh1, sh2;
    sb_sw_private_t k, k_inv;

    sb_hmac_drbg_state_t drbg;

    NULL_DRBG_INIT(&drbg);

    SB_TEST_ASSERT_SUCCESS(sb_sw_decompress_public_key(&ct, &p_zero, &zero, 0, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(sb_sw_decompress_public_key(&ct, &p_zero_pos, &zero, 1, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));

    SB_TEST_ASSERT_EQUAL(p_zero.bytes, zero.bytes, SB_ELEM_BYTES);
    SB_TEST_ASSERT((p_zero.bytes[2 * SB_ELEM_BYTES - 1] & 1) == 0);

    SB_TEST_ASSERT_EQUAL(p_zero_pos.bytes, zero.bytes, SB_ELEM_BYTES);
    SB_TEST_ASSERT((p_zero_pos.bytes[2 * SB_ELEM_BYTES - 1] & 1) == 1);

    _Bool sign;
    sb_sw_compressed_t zero_comp;

    SB_TEST_ASSERT_SUCCESS(sb_sw_compress_public_key(&ct, &zero_comp, &sign, &p_zero, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(zero, zero_comp);
    SB_TEST_ASSERT(sign == 0);

    SB_TEST_ASSERT_SUCCESS(sb_sw_compress_public_key(&ct, &zero_comp, &sign, &p_zero_pos, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(zero, zero_comp);
    SB_TEST_ASSERT(sign == 1);

    SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &k, &drbg, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(sb_sw_invert_private_key(&ct, &k_inv, &k, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));

    SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&ct, &sh1, &k, &p_zero, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_NOT_EQUAL(p_zero, sh1);

    SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&ct, &sh2, &k_inv, &sh1, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(p_zero, sh2);

    SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &k, &drbg, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(sb_sw_invert_private_key(&ct, &k_inv, &k, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));

    SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&ct, &sh1, &k, &p_zero_pos, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_NOT_EQUAL(p_zero_pos, sh1);

    SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&ct, &sh2, &k_inv, &sh1, NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(p_zero_pos, sh2);

    return 1;
}

// Created for use in sb_test_shared_secret_secp256k1.
// Also used in sb_test_sw_invalid_scalar as a valid public key for
// secp256k1
static const sb_sw_public_t TEST_PUB_SECP256K1 = {
    {
        0x6D, 0x98, 0x65, 0x44, 0x57, 0xFF, 0x52, 0xB8,
        0xCF, 0x1B, 0x81, 0x26, 0x5B, 0x80, 0x2A, 0x5B,
        0xA9, 0x7F, 0x92, 0x63, 0xB1, 0xE8, 0x80, 0x44,
        0x93, 0x35, 0x13, 0x25, 0x91, 0xBC, 0x45, 0x0A,
        0x53, 0x5C, 0x59, 0xF7, 0x32, 0x5E, 0x5D, 0x2B,
        0xC3, 0x91, 0xFB, 0xE8, 0x3C, 0x12, 0x78, 0x7C,
        0x33, 0x7E, 0x4A, 0x98, 0xE8, 0x2A, 0x90, 0x11,
        0x01, 0x23, 0xBA, 0x37, 0xDD, 0x76, 0x9C, 0x7D
    }};

// This shared-secret unit test is shamelessly borrowed from libsecp256k1.
_Bool sb_test_shared_secret_secp256k1(void)
{
    static const sb_sw_private_t d = {
        {
            0x64, 0x9D, 0x4F, 0x77, 0xC4, 0x24, 0x2D, 0xF7,
            0x7F, 0x20, 0x79, 0xC9, 0x14, 0x53, 0x03, 0x27,
            0xA3, 0x1B, 0x87, 0x6A, 0xD2, 0xD8, 0xCE, 0x2A,
            0x22, 0x36, 0xD5, 0xC6, 0xD7, 0xB2, 0x02, 0x9B
        }};
    static const sb_sw_shared_secret_t s = {
        {
            0x23, 0x77, 0x36, 0x84, 0x4D, 0x20, 0x9D, 0xC7,
            0x09, 0x8A, 0x78, 0x6F, 0x20, 0xD0, 0x6F, 0xCD,
            0x07, 0x0A, 0x38, 0xBF, 0xC1, 0x1A, 0xC6, 0x51,
            0x03, 0x00, 0x43, 0x19, 0x1E, 0x2A, 0x87, 0x86
        }};
    sb_sw_shared_secret_t out;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_shared_secret(&ct, &out, &d, &TEST_PUB_SECP256K1, NULL,
                            SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(s, out);
    return 1;
}

// Sample message digest from RFC 6979 p.32 sha256("sample").
static const sb_sw_message_digest_t TEST_MESSAGE = {
    {
        0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
        0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
        0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
        0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF
    }
};

// Signature for TEST_MESSAGE from RFC 6979 p.32
static const sb_sw_signature_t TEST_SIG = {
    {
        0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD,
        0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
        0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
        0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
        0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41,
        0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
        0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
        0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8
    }
};

// A simple unit test of RFC6979 deterministic message signing.
_Bool sb_test_sign_rfc6979(void)
{
    sb_sw_context_t ct;
    sb_sw_signature_t out;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &out, &TEST_PRIV_2, &TEST_MESSAGE,
                                  NULL, SB_SW_CURVE_P256,
                                  SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(TEST_SIG, out);
    return 1;
}

// Test RFC6979 deterministic whole-message signing, as well as verification
// of the resulting signature.
_Bool sb_test_sign_rfc6979_sha256(void)
{
    sb_sw_context_t ct;
    sb_sw_signature_t out;
    static const sb_byte_t orig_message[] = "sample";
    sb_sw_message_digest_t dig;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_sha256(&ct, &dig, &out, &TEST_PRIV_2,
                                  orig_message, sizeof(orig_message) - 1,
                                  NULL, SB_SW_CURVE_P256,
                                  SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(TEST_MESSAGE, dig);
    SB_TEST_ASSERT_EQUAL(TEST_SIG, out);

    SB_NULLIFY(&dig);

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_verify_signature_sha256(&ct, &dig, &out, &TEST_PUB_2,
                                      orig_message, sizeof(orig_message) - 1,
                                      NULL, SB_SW_CURVE_P256,
                                      SB_DATA_ENDIAN_BIG)
    );
    SB_TEST_ASSERT_EQUAL(TEST_MESSAGE, dig);

    // Test the incremental counterparts
    sb_sha256_state_t sha;
    sb_sha256_init(&sha);
    sb_sha256_update(&sha, orig_message, sizeof(orig_message) - 1);

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_sha256_start(&ct, &sha, &TEST_PRIV_2, NULL,
                                        SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    _Bool finished = 0;
    do {
        SB_TEST_ASSERT_SUCCESS(sb_sw_sign_message_digest_continue(&ct,
                                                                  &finished));
    } while (!finished);

    // Also test "over-continuing" signing
    SB_TEST_ASSERT_SUCCESS(sb_sw_sign_message_digest_continue(&ct,
                                                              &finished));
    SB_TEST_ASSERT(finished);

    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest_finish(&ct, &out, SB_DATA_ENDIAN_BIG));

    SB_TEST_ASSERT_EQUAL(TEST_MESSAGE, dig);
    SB_TEST_ASSERT_EQUAL(TEST_SIG, out);

    sb_sha256_init(&sha);
    sb_sha256_update(&sha, orig_message, sizeof(orig_message) - 1);
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_verify_signature_sha256_start(&ct, &sha, &TEST_SIG,
                                            &TEST_PUB_2, NULL, SB_SW_CURVE_P256,
                                            SB_DATA_ENDIAN_BIG)
    );

    finished = 0;

    do {
        SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature_continue(&ct, &finished));
    } while (!finished);

    // Also test "over-continuing" verification
    SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature_continue(&ct, &finished));
    SB_TEST_ASSERT(finished);

    SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature_finish(&ct));

    return 1;
}

// Unit test for secp256k1 signing.
_Bool sb_test_sign_secp256k1(void)
{
    static const sb_sw_message_digest_t m = {
        {
            0x4B, 0x68, 0x8D, 0xF4, 0x0B, 0xCE, 0xDB, 0xE6,
            0x41, 0xDD, 0xB1, 0x6F, 0xF0, 0xA1, 0x84, 0x2D,
            0x9C, 0x67, 0xEA, 0x1C, 0x3B, 0xF6, 0x3F, 0x3E,
            0x04, 0x71, 0xBA, 0xA6, 0x64, 0x53, 0x1D, 0x1A
        }};
    static const sb_sw_private_t d = {
        {
            0xEB, 0xB2, 0xC0, 0x82, 0xFD, 0x77, 0x27, 0x89,
            0x0A, 0x28, 0xAC, 0x82, 0xF6, 0xBD, 0xF9, 0x7B,
            0xAD, 0x8D, 0xE9, 0xF5, 0xD7, 0xC9, 0x02, 0x86,
            0x92, 0xDE, 0x1A, 0x25, 0x5C, 0xAD, 0x3E, 0x0F
        }};
    static const sb_sw_public_t p = {
        {
            0x77, 0x9D, 0xD1, 0x97, 0xA5, 0xDF, 0x97, 0x7E,
            0xD2, 0xCF, 0x6C, 0xB3, 0x1D, 0x82, 0xD4, 0x33,
            0x28, 0xB7, 0x90, 0xDC, 0x6B, 0x3B, 0x7D, 0x44,
            0x37, 0xA4, 0x27, 0xBD, 0x58, 0x47, 0xDF, 0xCD,
            0xE9, 0x4B, 0x72, 0x4A, 0x55, 0x5B, 0x6D, 0x01,
            0x7B, 0xB7, 0x60, 0x7C, 0x3E, 0x32, 0x81, 0xDA,
            0xF5, 0xB1, 0x69, 0x9D, 0x6E, 0xF4, 0x12, 0x49,
            0x75, 0xC9, 0x23, 0x7B, 0x91, 0x7D, 0x42, 0x6F
        }};

    sb_sw_signature_t out;
    sb_sw_public_t pub_out;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_public_key(&ct, &p, SB_SW_CURVE_SECP256K1,
                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &pub_out, &d, NULL,
                                                    SB_SW_CURVE_SECP256K1,
                                                    SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(pub_out, p);
    SB_TEST_ASSERT_SUCCESS(sb_sw_sign_message_digest(&ct, &out, &d, &m, NULL,
                                                     SB_SW_CURVE_SECP256K1,
                                                     SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature(&ct, &out, &p, &m, NULL,
                                                  SB_SW_CURVE_SECP256K1,
                                                  SB_DATA_ENDIAN_BIG));
    return 1;
}

// This test verifies that signing different messages with the same DRBG
// state will not result in catastrophic per-signature secret reuse. Adding
// the private key and digest to the DRBG's input should combat this.
_Bool sb_test_sign_catastrophe(void)
{
    sb_sw_context_t ct;
    sb_sw_signature_t s, s2, s3;
    sb_sw_message_digest_t m = TEST_MESSAGE;
    sb_hmac_drbg_state_t drbg;

    // Initialize drbg to predictable state
    NULL_DRBG_INIT(&drbg);

    // Sign message
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &s, &TEST_PRIV_1, &m, &drbg,
                                  SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));

    // Reinitialize drbg state
    NULL_DRBG_INIT(&drbg);

    // Sign the same message, which should produce the same signature
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &s2, &TEST_PRIV_1, &m, &drbg,
                                  SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(s, s2);

    // Reinitialize drbg state
    NULL_DRBG_INIT(&drbg);

    // Sign a different message, which should produce a different R because a
    // different k was used!
    m.bytes[0] ^= 1;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &s3, &TEST_PRIV_1, &m, &drbg,
                                  SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_NOT_EQUAL(s, s3, 32);

    // For manual verification: if you break sb_sw_sign_message_digest by
    // only providing the private key as additional data to the first
    // generate call, this test will fail!
    return 1;
}

// A simple unit test of signature verification.
_Bool sb_test_verify(void)
{
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_PUB_2, &TEST_MESSAGE,
                               NULL, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    return 1;
}

static const sb_sw_public_t JAMES_PUB = {
    {
        0x1E, 0xC1, 0x57, 0xEF, 0x96, 0x76, 0xEC, 0x55,
        0x91, 0x08, 0x6B, 0x83, 0xD1, 0xEB, 0xE0, 0xB4,
        0xC7, 0xF8, 0x7D, 0x6E, 0xC0, 0x99, 0x90, 0x3E,
        0x76, 0x48, 0x2F, 0x3F, 0x85, 0x2E, 0x60, 0x2D,
        0x61, 0xFB, 0x94, 0x43, 0x53, 0xF5, 0x6C, 0x08,
        0x22, 0x33, 0xB6, 0xB5, 0x0B, 0xA6, 0x26, 0x69,
        0x32, 0x28, 0xDD, 0x48, 0xFB, 0xEF, 0xBF, 0xFC,
        0xAD, 0xEB, 0x07, 0x98, 0x28, 0xAC, 0x75, 0xA3
    }
};

static const sb_sw_message_digest_t JAMES_MESSAGE = {
    {
        0xA5, 0xF0, 0x37, 0x8B, 0xFD, 0xC5, 0x51, 0x5D,
        0x0F, 0x06, 0xDC, 0x76, 0xD2, 0xFE, 0xC9, 0xB4,
        0x2E, 0x38, 0xB9, 0xB9, 0x54, 0x1F, 0x78, 0xA4,
        0x8F, 0x60, 0xDD, 0x17, 0x4F, 0x4D, 0x09, 0xBE
    }
};

static const sb_sw_message_digest_t JAMES_MESSAGE_2 = {
    {
        0xB2, 0xBB, 0x18, 0xF5, 0x5D, 0xFC, 0x60, 0x0D,
        0x20, 0x40, 0x1C, 0x65, 0x61, 0xC8, 0x5E, 0xA7,
        0x35, 0xAA, 0xBD, 0x37, 0xE7, 0x28, 0x09, 0xEA,
        0x6E, 0xB4, 0x1C, 0xBB, 0x4F, 0x46, 0xD9, 0x55
    }
};

static const sb_sw_signature_t JAMES_SIG = {
    {
        0xE7, 0xA8, 0xE2, 0x4F, 0xCB, 0x54, 0x0B, 0xF1,
        0x01, 0xC5, 0x0F, 0x8C, 0xA5, 0x56, 0x26, 0x37,
        0x17, 0x42, 0x24, 0xA1, 0xEF, 0x98, 0xCD, 0xC1,
        0xA0, 0xD9, 0x20, 0x2A, 0x17, 0x8D, 0xC3, 0xBE,
        0x0D, 0xA6, 0x92, 0xAC, 0x50, 0xFF, 0xF5, 0xA0,
        0x0C, 0x81, 0x73, 0x07, 0x48, 0x70, 0xDC, 0x90,
        0x82, 0x89, 0x06, 0x6C, 0xC3, 0xEF, 0x18, 0xD5,
        0xA1, 0xC4, 0xC7, 0x65, 0x55, 0xE1, 0xF9, 0x1A
    }
};

static const sb_sw_signature_t JAMES_SIG_2 = {
    {
        0xBC, 0xE3, 0x6A, 0x01, 0x57, 0x47, 0x31, 0xE7,
        0xF5, 0xE5, 0x4B, 0xA1, 0x3B, 0xDA, 0x16, 0x0F,
        0x99, 0xBE, 0xEF, 0xDE, 0x78, 0xAD, 0xA3, 0xA7,
        0x8E, 0x8F, 0x31, 0xD3, 0x55, 0xBE, 0xD6, 0xF8,
        0xDF, 0x17, 0x5C, 0xFC, 0xA8, 0xD7, 0x57, 0x10,
        0xE8, 0xDC, 0xD5, 0xE8, 0xD3, 0x59, 0xEB, 0xA2,
        0x46, 0xF5, 0x32, 0x26, 0x64, 0xCE, 0xD2, 0x15,
        0x80, 0xE1, 0xF6, 0x9B, 0x13, 0xA7, 0x88, 0xB5
    }
};

// Another unit test of signature verification, using signatures generated in
// an iPhone device's secure enclave. (Thanks, James.)
_Bool sb_test_verify_james(void)
{
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_verify_signature(&ct, &JAMES_SIG, &JAMES_PUB, &JAMES_MESSAGE,
                               NULL, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_verify_signature(&ct, &JAMES_SIG_2, &JAMES_PUB,
                               &JAMES_MESSAGE_2,
                               NULL, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    return 1;
}

// Test that verifying an invalid signature fails with the correct
// indication, and that verifying a signature with an invalid public key will
// fail with the correct indication.
_Bool sb_test_verify_invalid(void)
{
    sb_sw_context_t ct;
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_PUB_1, &TEST_MESSAGE,
                               NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_SIGNATURE_INVALID);

    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_SIG, &TEST_MESSAGE,
                               NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PUBLIC_KEY_INVALID);
    return 1;
}

// Once a candidate r was successfully decompressed such that F = (r, _) is a
// valid point on the curve, we compute pk = (-z * r^-1) * g + (s * r^-1) * F
// which is computed using Shamir's trick. z is dependent on the message
// digest which is fixed below and s is a fixed value.
static void pk_recovery(sb_sw_context_t* m, sb_sw_curve_t const* s)
{
    // F is in MULT_POINT

    sb_fe_mont_convert(C_T5(m), VERIFY_QR(m), s->n); // t5 = r * R
    sb_fe_mod_inv_r(C_T5(m), C_T6(m), C_T7(m), s->n); // t5 = r^-1 * R

    *C_T6(m) = *VERIFY_MESSAGE(m);
    *C_T7(m) = *VERIFY_QS(m);

    sb_fe_mont_mult(MULT_ADD_KG(m), C_T6(m), C_T5(m), s->n); // kG = z * r^-1
    sb_fe_mod_negate(MULT_ADD_KG(m), MULT_ADD_KG(m), s->n); // kG = -z * r^-1

    sb_fe_mont_mult(MULT_K(m), C_T7(m), C_T5(m), s->n); // kP = s * r^-1

    *MULT_Z(m) = SB_FE_ONE;

    sb_sw_point_mult_add_z(m, s);

    // invert final Z
    sb_fe_mod_inv_r(MULT_Z(m), C_T5(m), C_T6(m), s->p); // Z = z^-1 * R

    sb_fe_mont_square(C_T6(m), MULT_Z(m), s->p); // t6 = z^-2 * R
    sb_fe_mont_mult(C_T7(m), C_T6(m), MULT_Z(m), s->p); // t7 = z^-3 * R

    sb_fe_mont_mult(C_X2(m), C_X1(m), C_T6(m), s->p); // x2 = x1 * z^-2
    sb_fe_mont_mult(C_Y2(m), C_Y1(m), C_T7(m), s->p); // y2 = y1 * z^-3
}

// Extracts the message digest, (r,s) values of the signature and places them
// in the context. Reduces them mod n, which doesn't change their value but
// ensures that the fe struct keeps track of what prime it was reduced under.
static void extract_sig_components(sb_sw_context_t* m,
                                   sb_sw_signature_t const* sig,
                                   sb_sw_message_digest_t const* message,
                                   sb_sw_curve_t const* s,
                                   sb_data_endian_t e)
{
    sb_fe_from_bytes(VERIFY_MESSAGE(m), message->bytes, e);
    sb_fe_from_bytes(VERIFY_QR(m), sig->bytes, e);
    sb_fe_from_bytes(VERIFY_QS(m), sig->bytes + SB_ELEM_BYTES, e);

    *MULT_POINT_X(m) = *VERIFY_QR(m);

    sb_fe_mod_reduce(VERIFY_QR(m), s->n);
    sb_fe_mod_reduce(VERIFY_QS(m), s->n);
    sb_fe_mod_reduce(VERIFY_MESSAGE(m), s->n);
}

// Returns the number of possible public keys corresponding to the given
// signature and message digest (0, 2, or 4), and the public keys in the out
// parameter.

// For each signature, there are up to four public keys that could have
// signed the message:
// 0, if the signature is not valid (neither r nor N + r is the X coordinate
// of a point on the given curve)
// 2, if one of the following is true:
//    * r > P - N
//    * r <= P - N and r is the X component of a point on the curve, but N +
//      r is not
//    * r <= P - N and N + r is the X component of a point on the curve, but
//      r is not
// 4, if r <= P - N and both r and N + r are X components of points on the curve
static size_t verify_recover_public_key(sb_sw_public_t keys[4],
                                        sb_sw_signature_t const* sig,
                                        sb_sw_message_digest_t const* message,
                                        sb_sw_curve_t const* s,
                                        sb_data_endian_t e)
{
    sb_sw_context_t m;
    SB_NULLIFY(&m);
    size_t i = 0;

    extract_sig_components(&m, sig, message, s, e);
    SB_TEST_IF_POISON(sb_sw_point_decompress(&m, 0, s)) {

        pk_recovery(&m, s);

        sb_fe_to_bytes(keys[i].bytes, C_X2(&m), e);
        sb_fe_to_bytes(keys[i].bytes + SB_ELEM_BYTES, C_Y2(&m), e);

        i++;

        // re-extract scalars...
        extract_sig_components(&m, sig, message, s, e);

        sb_sw_point_decompress(&m, 1, s);

        pk_recovery(&m, s);

        sb_fe_to_bytes(keys[i].bytes, C_X2(&m), e);
        sb_fe_to_bytes(keys[i].bytes + SB_ELEM_BYTES, C_Y2(&m), e);

        i++;
    }

    extract_sig_components(&m, sig, message, s, e);
    sb_fe_sub(C_T5(&m), &s->p->p, &s->n->p); // t5 = P - N
    SB_TEST_IF_POISON(sb_fe_lt(VERIFY_QR(&m), C_T5(&m)) |
                      sb_fe_equal(VERIFY_QR(&m), C_T5(&m))) {
        *C_T5(&m) = s->n->p; // t5 = N
        sb_fe_mod_reduce(C_T5(&m), s->p); // N is reduced mod P
        sb_fe_mod_reduce(MULT_POINT_X(&m), s->p); // likewise
        sb_fe_mod_add(MULT_POINT_X(&m), MULT_POINT_X(&m), C_T5(&m), s->p); //
        // x = x + N

        if (sb_sw_point_decompress(&m, 0, s)) {

            pk_recovery(&m, s);

            sb_fe_to_bytes(keys[i].bytes, C_X2(&m), e);
            sb_fe_to_bytes(keys[i].bytes + SB_ELEM_BYTES, C_Y2(&m), e);

            i++;

            // re-extract scalars...
            extract_sig_components(&m, sig, message, s, e);

            *C_T5(&m) = s->n->p; // t5 = N
            sb_fe_mod_reduce(C_T5(&m), s->p); // N is reduced mod P
            sb_fe_mod_reduce(MULT_POINT_X(&m), s->p); // likewise
            sb_fe_mod_add(MULT_POINT_X(&m), MULT_POINT_X(&m), C_T5(&m),
                          s->p); //
            // x = x + N

            sb_sw_point_decompress(&m, 1, s);

            pk_recovery(&m, s);

            sb_fe_to_bytes(keys[i].bytes, C_X2(&m), e);
            sb_fe_to_bytes(keys[i].bytes + SB_ELEM_BYTES, C_Y2(&m), e);

            i++;
        }
    }

    return i;
}

// sha256("one small step for man")
static const sb_sw_message_digest_t TEST_MESSAGE_PKR = {
    .bytes = {
        0x33, 0x2A, 0x2D, 0x20, 0x53, 0x1C, 0x0F, 0xD5,
        0x1A, 0x6F, 0x4C, 0x1B, 0x49, 0x69, 0xA8, 0x9C,
        0xA0, 0xB2, 0x65, 0x07, 0x69, 0x17, 0x64, 0xE3,
        0x9F, 0xEB, 0x82, 0xEC, 0x22, 0xAC, 0x75, 0x11
    }
};

//We can set s to anything as we don't care about the secret key so we fix it
// to this value.
static const sb_single_t TEST_S_PKR = {
    .bytes = {
        0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
        0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
        0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
        0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55
    }
};

// This test generates a signature (r, s) of the message digest in
// TEST_MESSAGE_PKR which has a small r (< P - N). When
// verify_recover_public_key returns four potential public keys, this
// indicates that N + r corresponds to the X component of a point on the
// curve, and for the second two public keys returned, the X component of the
// point computed during signature verification is equal to N + r.
static _Bool test_small_r_signature(sb_sw_curve_id_t curve)
{
    sb_fe_t candidate_r = SB_FE_ONE;
    sb_sw_signature_t sig;
    sb_sw_public_t keys[4];
    sb_sw_context_t m;
    sb_sw_curve_t const* s;
    size_t t = 0;

    SB_TEST_ASSERT_SUCCESS(sb_sw_curve_from_id(&s, curve));

    do {
        sb_fe_to_bytes(sig.bytes, &candidate_r, SB_DATA_ENDIAN_BIG);
        memcpy(sig.bytes + SB_ELEM_BYTES, TEST_S_PKR.bytes, SB_ELEM_BYTES);

        const size_t c = verify_recover_public_key(keys, &sig,
                                                   &TEST_MESSAGE_PKR,
                                                   s, SB_DATA_ENDIAN_BIG);

        // Verify the signature for each candidate public key that was returned
        for (size_t i = 0; i < c; i++) {
            SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature(&m, &sig,
                                                          &keys[i],
                                                          &TEST_MESSAGE_PKR,
                                                          NULL, curve,
                                                          SB_DATA_ENDIAN_BIG));
        }

        if (c == 4) {
            // all cases have been covered
            return 1;
        }

        sb_fe_add(&candidate_r, &candidate_r, &SB_FE_ONE);

        t++;
        SB_TEST_ASSERT(t < 1024); // we should find a candidate on any curve pretty quickly
    } while (1);
}

// When verifying signatures it is possible to have a signature that won't
// verify for the given r value, as it is reduced mod n. Then it becomes
// necessary to verify the signature (n + r, s). This case is not common, so
// it is tested separately using pk recovery. Tests on p256.
_Bool sb_test_small_r_signature_p256(void)
{
    return test_small_r_signature(SB_SW_CURVE_P256);
}

// The same test as above but for secp256k1.
_Bool sb_test_small_r_signature_secp256k1(void)
{
    return test_small_r_signature(SB_SW_CURVE_SECP256K1);
}

// Test the boundary case of (P - N, s).
static _Bool test_small_r_boundary(sb_sw_curve_id_t curve)
{
    sb_sw_curve_t const* s;

    SB_TEST_ASSERT_SUCCESS(sb_sw_curve_from_id(&s, curve));

    sb_fe_t candidate_r;
    sb_fe_sub(&candidate_r, &s->p->p, &s->n->p);

    sb_sw_signature_t sig;
    sb_sw_public_t keys[4];
    sb_sw_context_t m;

    sb_fe_to_bytes(sig.bytes, &candidate_r, SB_DATA_ENDIAN_BIG);
    memcpy(sig.bytes + SB_ELEM_BYTES, TEST_S_PKR.bytes, SB_ELEM_BYTES);

    const size_t c = verify_recover_public_key(keys, &sig,
                                               &TEST_MESSAGE_PKR,
                                               s, SB_DATA_ENDIAN_BIG);

    // Verify the signature for each candidate public key that was returned
    for (size_t i = 0; i < c; i++) {
        SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature(&m, &sig,
                                                      &keys[i],
                                                      &TEST_MESSAGE_PKR,
                                                      NULL, curve,
                                                      SB_DATA_ENDIAN_BIG));
    }

    return 1;
}

// Tests for correctness of signature verification for p256 specifically for
// the case where r = p - n.
_Bool sb_test_small_r_boundary_p256(void)
{
    return test_small_r_boundary(SB_SW_CURVE_P256);
}

// Same test as above but for secp256k1.
_Bool sb_test_small_r_boundary_secp256k1(void)
{
    return test_small_r_boundary(SB_SW_CURVE_SECP256K1);
}

// A simple unit test of public key recovery. Tests going backwards in
// signing a message returns correct pk. Experimentally confirmed that
// the second recovered pk = TEST_PUB_2
_Bool sb_test_pk_recovery(void)
{
    sb_sw_public_t recovered[4];
    SB_TEST_ASSERT(verify_recover_public_key(recovered, &TEST_SIG,
                                             &TEST_MESSAGE, &SB_CURVE_P256,
                                             SB_DATA_ENDIAN_BIG) == 2);
    SB_TEST_ASSERT_EQUAL(recovered[0].bytes, TEST_PUB_2);
    return 1;
}

// A second unit test of public key recovery. Verifies that the same public
// key is recovered for two different message digest / signature pairs.
_Bool sb_test_pk_recovery_james(void)
{
    sb_sw_public_t recovered[4];
    SB_TEST_ASSERT(verify_recover_public_key(recovered, &JAMES_SIG,
                                             &JAMES_MESSAGE, &SB_CURVE_P256,
                                             SB_DATA_ENDIAN_BIG) == 2);
    SB_TEST_ASSERT_EQUAL(recovered[1].bytes, JAMES_PUB);
    SB_TEST_ASSERT(verify_recover_public_key(recovered, &JAMES_SIG_2,
                                             &JAMES_MESSAGE_2, &SB_CURVE_P256,
                                             SB_DATA_ENDIAN_BIG) == 2);
    SB_TEST_ASSERT_EQUAL(recovered[1].bytes, JAMES_PUB);
    return 1;
}

/* Verify that the correct number of candidates are tested when generating
 * private scalars. Fills the candidate random values with all 0xFF bytes to
 * ensure that with 0-3 bad candidates we know that the others must be tested
 * . If all candidates are bad then a DRBG error should be raised.
 */
_Bool sb_test_candidates(void)
{
    sb_hmac_drbg_state_t drbg;

    sb_sw_context_t ct;
    sb_single_t k, prev_k;
    sb_double_t sig, prev_sig;

    memset(&prev_k, 0, sizeof(prev_k));
    memset(&prev_sig, 0, sizeof(prev_sig));

    for (size_t i = 0; i <= SB_SW_FIPS186_4_CANDIDATES; i++) {
        NULL_DRBG_INIT(&drbg);
        drbg.dangerous_nonsense_count = i;

        if (i < SB_SW_FIPS186_4_CANDIDATES) {
            SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &k, &drbg,
                                                              SB_SW_CURVE_P256,
                                                              SB_DATA_ENDIAN_BIG));
            SB_TEST_ASSERT_NOT_EQUAL(k, prev_k);
        } else {
            SB_TEST_ASSERT_ERROR(sb_sw_generate_private_key(&ct, &k, &drbg,
                                                            SB_SW_CURVE_P256,
                                                            SB_DATA_ENDIAN_BIG),
                                 SB_ERROR_DRBG_FAILURE);
        }

        prev_k = k;
    }

    for (size_t i = 0; i <= SB_SW_FIPS186_4_CANDIDATES; i++) {
        NULL_DRBG_INIT(&drbg);
        drbg.dangerous_nonsense_count = i;

        if (i < SB_SW_FIPS186_4_CANDIDATES) {
            SB_TEST_ASSERT_SUCCESS(sb_sw_sign_message_digest(&ct, &sig,
                                                             &TEST_PRIV_2,
                                                             &TEST_MESSAGE,
                                                             &drbg,
                                                             SB_SW_CURVE_P256,
                                                             SB_DATA_ENDIAN_BIG));
            SB_TEST_ASSERT_NOT_EQUAL(sig, prev_sig);
            SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature(&ct, &sig,
                                                          &TEST_PUB_2,
                                                          &TEST_MESSAGE, NULL,
                                                          SB_SW_CURVE_P256,
                                                          SB_DATA_ENDIAN_BIG));
        } else {
            SB_TEST_ASSERT_ERROR(sb_sw_sign_message_digest(&ct, &sig,
                                                           &TEST_PRIV_2,
                                                           &TEST_MESSAGE, &drbg,
                                                           SB_SW_CURVE_P256,
                                                           SB_DATA_ENDIAN_BIG),
                                 SB_ERROR_DRBG_FAILURE);
        }

        prev_sig = sig;
    }

    return 1;
}

// Test errors that are returned early, before any computation is done.
_Bool sb_test_sw_early_errors(void)
{
    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);
    drbg.reseed_counter = SB_HMAC_DRBG_RESEED_INTERVAL + 1;

    // Test that calling functions with an invalid curve and a DRBG that must
    // be reseeded fails with the correct error indications:
    sb_sw_context_t ct;
    sb_single_t s;
    sb_double_t d;
    SB_TEST_ASSERT_ERROR(sb_sw_generate_private_key(&ct, &s, &drbg,
                                                    SB_SW_CURVE_INVALID,
                                                    SB_DATA_ENDIAN_BIG),
                         SB_ERROR_CURVE_INVALID, SB_ERROR_RESEED_REQUIRED);
    SB_TEST_ASSERT_ERROR(sb_sw_compute_public_key(&ct, &d, &TEST_PRIV_1, &drbg,
                                                  SB_SW_CURVE_INVALID,
                                                  SB_DATA_ENDIAN_BIG),
                         SB_ERROR_CURVE_INVALID, SB_ERROR_RESEED_REQUIRED);
    SB_TEST_ASSERT_ERROR(sb_sw_valid_public_key(&ct, &d,
                                                SB_SW_CURVE_INVALID,
                                                SB_DATA_ENDIAN_BIG),
                         SB_ERROR_CURVE_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_shared_secret(&ct, &s, &TEST_PRIV_1, &TEST_PUB_1, &drbg,
                            SB_SW_CURVE_INVALID, SB_DATA_ENDIAN_BIG),
        SB_ERROR_CURVE_INVALID, SB_ERROR_RESEED_REQUIRED);
    SB_TEST_ASSERT_ERROR(
        sb_sw_sign_message_digest(&ct, &d, &TEST_PRIV_1, &TEST_MESSAGE,
                                  &drbg, SB_SW_CURVE_INVALID,
                                  SB_DATA_ENDIAN_BIG),
        SB_ERROR_CURVE_INVALID, SB_ERROR_RESEED_REQUIRED);
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_PUB_1, &TEST_MESSAGE,
                               &drbg, SB_SW_CURVE_INVALID,
                               SB_DATA_ENDIAN_BIG),
        SB_ERROR_CURVE_INVALID, SB_ERROR_RESEED_REQUIRED);
    SB_TEST_ASSERT_ERROR(
        sb_sw_composite_sign_wrap_message_digest(&ct, &s, &TEST_MESSAGE,
                                                 &TEST_PRIV_1, &drbg,
                                                 SB_SW_CURVE_INVALID,
                                                 SB_DATA_ENDIAN_BIG),
        SB_ERROR_CURVE_INVALID, SB_ERROR_RESEED_REQUIRED);
    SB_TEST_ASSERT_ERROR(
        sb_sw_composite_sign_unwrap_signature(&ct, &d, &TEST_SIG, &TEST_PRIV_1,
                                              SB_SW_CURVE_INVALID,
                                              SB_DATA_ENDIAN_BIG),
                        SB_ERROR_CURVE_INVALID);

    d = TEST_PUB_1;
    d.bytes[0] ^= 1;

    // Test that calling functions which accept a curve point fail with the
    // correct error indications when the point is not on the curve:

    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &d, &TEST_MESSAGE, NULL,
                               SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PUBLIC_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_shared_secret(&ct, &s, &TEST_PRIV_1, &d, NULL,
                            SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PUBLIC_KEY_INVALID);

    return 1;
}

// Test that calling functions which accept a private scalar fail when
// the private key is not valid for the specified curve.
//
_Bool sb_test_sw_invalid_scalar(void)
{
    const sb_sw_private_t bad_priv = {
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        }
    };

    sb_sw_context_t ct;
    sb_double_t d;
    sb_single_t s;

    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_private_key(&ct, &bad_priv,
                                SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_private_key(&ct, &bad_priv,
                                SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_sign_message_digest(&ct, &d, &bad_priv, &TEST_MESSAGE, NULL,
                                  SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_sign_message_digest(&ct, &d, &bad_priv, &TEST_MESSAGE, NULL,
                                  SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_compute_public_key(&ct, &d, &bad_priv, NULL,
                                 SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_compute_public_key(&ct, &d, &bad_priv, NULL,
                                 SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_invert_private_key(&ct, &s, &bad_priv, NULL,
                                 SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_invert_private_key(&ct, &s, &bad_priv, NULL,
                                 SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_point_multiply(&ct, &d, &bad_priv, &TEST_PUB_1, NULL,
                             SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    // Using big-endian here because TEST_PUB_SECP256K1 is defined in big-endian
    SB_TEST_ASSERT_ERROR(
        sb_sw_point_multiply(&ct, &d, &bad_priv, &TEST_PUB_SECP256K1, NULL,
                             SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_composite_sign_wrap_message_digest(
            &ct, &s, &TEST_MESSAGE, &bad_priv, NULL,
            SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_composite_sign_wrap_message_digest(
            &ct, &s, &TEST_MESSAGE, &bad_priv, NULL,
            SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_composite_sign_unwrap_signature(&ct, &d, &TEST_SIG, &bad_priv,
                                              SB_SW_CURVE_P256,
                                              SB_DATA_ENDIAN_BIG),
        SB_ERROR_PRIVATE_KEY_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_composite_sign_unwrap_signature(&ct, &d, &TEST_SIG, &bad_priv,
                                              SB_SW_CURVE_SECP256K1,
                                              SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PRIVATE_KEY_INVALID);

    return 1;
}

// Test that sweet-b is not vulnerable to the "Psychic Paper" attack.
// More specifically, verify that for some signature (r, s) if r or s = 0 or N
// signature verification returns invalid.
static _Bool sb_test_invalid_sig(const sb_byte_t invalid[static const SB_ELEM_BYTES],
                                 const sb_sw_curve_id_t c,
                                 const sb_data_endian_t e)
{
    sb_sw_signature_t s1, s2;
    sb_sw_context_t ct;
    sb_hmac_drbg_state_t drbg;

    NULL_DRBG_INIT(&drbg);

    sb_sw_private_t priv;
    sb_sw_public_t pub;
    
    // Generate a valid public key
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_generate_private_key(&ct, &priv, &drbg, c, e));
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_compute_public_key(&ct, &pub, &priv, &drbg, c, e));

    // Generate two random "signatures". We don't care that they are invalid.
    SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_generate_additional_dummy
                                    (&drbg, s1.bytes, sizeof(s1.bytes)));
    SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_generate_additional_dummy
                                    (&drbg, s2.bytes, sizeof(s2.bytes)));

    // Set half the signature to 0 or N and make sure we get an error 
    memcpy(s1.bytes, invalid, SB_ELEM_BYTES);
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &s1, &pub, 
                               &TEST_MESSAGE_PKR, &drbg, c, e), 
        SB_ERROR_SIGNATURE_INVALID);

    // Test with a signature with the other half as 0 or N and 
    // make sure we still get an error
    memcpy(s2.bytes + SB_ELEM_BYTES, invalid, SB_ELEM_BYTES);
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &s2, &pub, 
                              &TEST_MESSAGE_PKR, &drbg, c, e), 
        SB_ERROR_SIGNATURE_INVALID);

    // Make both r and s 0 or N and make sure we get an error
    memcpy(s2.bytes, invalid, SB_ELEM_BYTES);
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &s2, &pub, 
                               &TEST_MESSAGE_PKR, &drbg, c, e), 
        SB_ERROR_SIGNATURE_INVALID);

    return 1;
}

_Bool sb_test_sw_invalid_sig_p256(void) {
    sb_sw_curve_id_t c = SB_SW_CURVE_P256;
    sb_data_endian_t e = SB_DATA_ENDIAN_BIG;
    // Load up some buffers with the invalid signature values
    // 0 and N.
    sb_byte_t zeros[SB_ELEM_BYTES] = {0};

    sb_byte_t n[SB_ELEM_BYTES];
    const sb_sw_curve_t* s = NULL;
    SB_TEST_ASSERT_SUCCESS(sb_sw_curve_from_id(&s, c));

    sb_fe_to_bytes(n, &s->n->p, e);

    SB_TEST_ASSERT(sb_test_invalid_sig(zeros, c, e) == 1);
    SB_TEST_ASSERT(sb_test_invalid_sig(n, c, e) == 1);

    return 1;
}

_Bool sb_test_sw_invalid_sig_secp256k1(void) {
    sb_sw_curve_id_t c = SB_SW_CURVE_SECP256K1;
    sb_data_endian_t e = SB_DATA_ENDIAN_LITTLE;

    // Load up some buffers with the invalid signature values
    // 0 and N.
    sb_byte_t zeros[SB_ELEM_BYTES] = {0};

    sb_byte_t n[SB_ELEM_BYTES];
    const sb_sw_curve_t* s = NULL;
    SB_TEST_ASSERT_SUCCESS(sb_sw_curve_from_id(&s, c));

    sb_fe_to_bytes(n, &s->n->p, e);

    SB_TEST_ASSERT(sb_test_invalid_sig(zeros, c, e) == 1);
    SB_TEST_ASSERT(sb_test_invalid_sig(n, c, e) == 1);

    return 1;
}


/// Randomized tests:

// A randomized test of the composite key wrapping and unwrapping methods.
static _Bool sb_test_composite_key_wrap(const sb_sw_curve_id_t c,
                                        const sb_data_endian_t e)
{
    sb_sw_private_t sk, wk;
    sb_sw_public_t vk, ck;
    sb_sw_signature_t s, unwrapped;
    sb_sw_context_t ct;
    sb_sw_message_digest_t m, wrapped;
    size_t i = 0;

    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);
    do {
        // Generate a keypair (vk, sk) and a wrapping key wk.
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_generate_private_key(&ct, &sk, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_generate_private_key(&ct, &wk, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_compute_public_key(&ct, &vk, &sk, &drbg, c, e));

        // Create some random message digest.
        SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_generate_additional_dummy
                                    (&drbg, m.bytes, sizeof(m.bytes)));
        // Wrap the message digest and sign using sk.
        SB_TEST_ASSERT_SUCCESS(sb_sw_composite_sign_wrap_message_digest
                                    (&ct, &wrapped, &m, &wk, &drbg, c, e));

        SB_TEST_ASSERT_SUCCESS(sb_sw_sign_message_digest
                                    (&ct, &s, &sk, &wrapped, &drbg, c, e));
        // Unwrap the signature and compute the composite key.
        SB_TEST_ASSERT_SUCCESS(sb_sw_composite_sign_unwrap_signature
                                    (&ct, &unwrapped, &s, &wk, c, e));

        SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply
                                    (&ct, &ck, &wk, &vk, &drbg, c, e));

         // Verify the signature.
        SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature
                                    (&ct, &unwrapped, &ck, &m, &drbg, c, e));
        // Reseed the DRBG for the next iteration.
        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, sk.bytes, sizeof(sk),
                                          wk.bytes, sizeof(wk)));
        i++;
    } while (i < SB_TEST_RAND_COUNT);
    return 1;
}

_Bool sb_test_composite_key_wrap_p256(void)
{
    return sb_test_composite_key_wrap
            (SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);
}

_Bool sb_test_composite_key_wrap_secp256k1(void)
{
    return sb_test_composite_key_wrap
            (SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE);
}

// A randomized test of the Shamir's trick multiplication-addition routine.
_Bool sb_test_sw_point_mult_add_rand(void)
{
    sb_fe_t ka, kb, kc, kar, kbr, kcr;
    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);

    for (size_t i = 0; i < SB_TEST_RAND_COUNT; i++) {
        SB_TEST_ASSERT(generate_fe(&ka, &drbg));
        SB_TEST_ASSERT(generate_fe(&kb, &drbg));
        SB_TEST_ASSERT(generate_fe(&kc, &drbg));

        kar = ka;
        sb_fe_mod_reduce(&kar, SB_CURVE_P256.n);
        kbr = kb;
        sb_fe_mod_reduce(&kbr, SB_CURVE_P256.n);
        kcr = kc;
        sb_fe_mod_reduce(&kcr, SB_CURVE_P256.n);

        SB_TEST_ASSERT(test_sw_point_mult_add(&kar, &kbr, &kcr,
                                              &SB_CURVE_P256));

        kar = ka;
        sb_fe_mod_reduce(&kar, SB_CURVE_SECP256K1.n);
        kbr = kb;
        sb_fe_mod_reduce(&kbr, SB_CURVE_SECP256K1.n);
        kcr = kc;
        sb_fe_mod_reduce(&kcr, SB_CURVE_SECP256K1.n);

        SB_TEST_ASSERT(
            test_sw_point_mult_add(&kar, &kbr, &kcr, &SB_CURVE_SECP256K1));
        drbg.reseed_counter = 1;
    }
    return 1;
}

// Test inverting random private scalars for use in a blinding protocol.
// Specifically, verify that (((G^d)^k)^d2)^k_inv = (G^d)^d2 for random k
// values.
static _Bool sb_test_invert_iter_c(const sb_sw_curve_id_t c,
                                   const sb_data_endian_t e)
{
    sb_sw_private_t d, d2, k, k_inv, k_inv_2;
    sb_sw_public_t p, p2, p3;
    sb_sw_shared_secret_t s, s2, s3;
    sb_sw_context_t ct;
    size_t i = 0;

    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);

    // generate d and d2 in advance
    SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &d, &drbg, c, e));
    SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &d2, &drbg, c,
                                                      e));
    // p = G^d
    SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &p, &d, &drbg, c, e));

    // s3 = (G^d)^d2
    SB_TEST_ASSERT_SUCCESS(sb_sw_shared_secret(&ct, &s3, &d2, &p, &drbg,
                                               c, e));

    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                            TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2)));

    do {
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_generate_private_key(&ct, &k, &drbg, c, e));

        // p2 = (G^d)^k
        SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&ct, &p2, &k, &p, &drbg,
                                                    c, e));

        // s = ((G^d)^k)^d2
        SB_TEST_ASSERT_SUCCESS(sb_sw_shared_secret(&ct, &s, &d2, &p2, &drbg,
                                                   c, e));

        // p3 = decompressed s
        SB_TEST_ASSERT_SUCCESS(sb_sw_decompress_public_key(&ct, &p3, &s, 0,
                                                           c, e));

        // s2 = (((G^d)^k)^d2)^k_inv
        SB_TEST_ASSERT_SUCCESS(sb_sw_invert_private_key(&ct, &k_inv, &k,
                                                        &drbg, c, e));

        // Verify the same result is returned if no DRBG is supplied
        SB_TEST_ASSERT_SUCCESS(sb_sw_invert_private_key(&ct, &k_inv_2, &k,
                                                        NULL, c, e));
        SB_TEST_ASSERT_EQUAL(k_inv, k_inv_2);

        SB_TEST_ASSERT_SUCCESS(sb_sw_shared_secret(&ct, &s2, &k_inv, &p3,
                                                   &drbg, c, e));

        SB_TEST_ASSERT_EQUAL(s2, s3);

        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                                TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2)));
        i++;
    } while (i < SB_TEST_RAND_COUNT);
    return 1;
}

// Randomized test of private key inversion for P-256.
_Bool sb_test_invert_iter(void)
{
    return sb_test_invert_iter_c(SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);
}

// Randomized test of private key inversion for secp256k1.
_Bool sb_test_invert_iter_secp256k1(void)
{
    return sb_test_invert_iter_c(SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE);
}

// Randomized testing of point decompression, by generating random private
// scalars, computing the public key, compressing the public key, and then
// decompressing the same public key again.
static _Bool sb_test_decompress_iter_c(const sb_sw_curve_id_t c,
                                       const sb_data_endian_t e)
{
    sb_sw_private_t d;
    sb_sw_public_t p, p2;
    sb_sw_compressed_t x;
    _Bool sign;
    sb_sw_context_t ct;
    size_t i = 0;

    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);
    do {
        SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &d, &drbg, c,
                                                          e));
        SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &p, &d, &drbg, c,
                                                        e));
        SB_TEST_ASSERT_SUCCESS(sb_sw_compress_public_key(&ct, &x, &sign, &p,
                                                         c,
                                                         e));
                                              
        // Verify that the low bit matches the produced sign.
        SB_TEST_ASSERT((p.bytes[e == SB_DATA_ENDIAN_BIG ? 2 * SB_ELEM_BYTES - 1 : SB_ELEM_BYTES] & 1) == sign);
        SB_TEST_ASSERT_SUCCESS(sb_sw_decompress_public_key(&ct, &p2, &x,
                                                           sign, c,
                                                           e));
        SB_TEST_ASSERT_EQUAL(p, p2);
        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                                TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2))
        );
        i++;
    } while (i < SB_TEST_RAND_COUNT);
    return 1;
}

// Test public key decompression on P-256.
_Bool sb_test_decompress_iter(void)
{
    return sb_test_decompress_iter_c(SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);
}

// Test public key decompression on secp256k1
_Bool sb_test_decompress_iter_secp256k1(void)
{
    return sb_test_decompress_iter_c(SB_SW_CURVE_SECP256K1,
                                     SB_DATA_ENDIAN_LITTLE);
}

// Test decompressing random X values. If the X value is valid, test
// decompressing it with the other "sign" bit, and that the resulting public
// keys are valid.
static _Bool sb_test_decompress_rand_c(const sb_sw_curve_id_t c,
                                       const sb_data_endian_t e)
{
    sb_sw_public_t p, p2;
    sb_sw_compressed_t x, x2;
    _Bool sign;
    sb_sw_context_t ct;
    size_t i = 0;

    _Bool found_valid = 0;
    _Bool found_invalid = 0;

    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);
    do {
        SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_generate_additional_dummy
                                   (&drbg, x.bytes, SB_ELEM_BYTES));
        sb_error_t err = sb_sw_decompress_public_key(&ct, &p, &x,
                                                     0, c, e);
        SB_TEST_ASSERT(err == SB_SUCCESS || err == SB_ERROR_PUBLIC_KEY_INVALID);
        if (err == SB_SUCCESS) {
            found_valid = 1;
            SB_TEST_ASSERT_SUCCESS(sb_sw_decompress_public_key(&ct, &p2, &x,
                                                               1, c,
                                                               e));
            SB_TEST_ASSERT_SUCCESS(sb_sw_valid_public_key(&ct, &p, c,
                                                          e));
            SB_TEST_ASSERT_SUCCESS(sb_sw_valid_public_key(&ct, &p2, c,
                                                          e));
            SB_TEST_ASSERT_SUCCESS(sb_sw_compress_public_key(&ct, &x2, &sign,
                                                             &p, c,
                                                             e));
            SB_TEST_ASSERT_EQUAL(x, x2);
            SB_TEST_ASSERT(sign == 0);
            SB_TEST_ASSERT_SUCCESS(sb_sw_compress_public_key(&ct, &x2, &sign,
                                                             &p2, c,
                                                             e));
            SB_TEST_ASSERT_EQUAL(x, x2);
            SB_TEST_ASSERT(sign == 1);
        } else {
            found_invalid = 1;
        }
        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                                TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2))
        );
        i++;
    } while (i < SB_TEST_RAND_COUNT);

    SB_TEST_ASSERT(found_valid && found_invalid);
    return 1;
}

// Test decompressing random values on the P-256 curve.
_Bool sb_test_decompress_rand(void)
{
    return sb_test_decompress_rand_c(SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);
}

// Test decompressing random values on the secp2561k curve.
_Bool sb_test_decompress_rand_secp256k1(void)
{
    return sb_test_decompress_rand_c(SB_SW_CURVE_SECP256K1,
                                     SB_DATA_ENDIAN_LITTLE);
}

// Randomized test of ECDH, using random private keys.
// Tests not only shared_secret but also point_multiply then compress.
static _Bool sb_test_shared_iter_c(const sb_sw_curve_id_t c,
                                   const sb_data_endian_t e)
{
    sb_sw_private_t d, d2;
    sb_sw_public_t p, p2, p3, p4;
    sb_sw_shared_secret_t s, s2;
    sb_sw_compressed_t x;
    _Bool sg;
    sb_sw_context_t ct;
    size_t i = 0;

    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);
    do {
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_generate_private_key(&ct, &d, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_compute_public_key(&ct, &p, &d, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_generate_private_key(&ct, &d2, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_compute_public_key(&ct, &p2, &d2, &drbg, c, e));

        SB_TEST_ASSERT_SUCCESS(
            sb_sw_shared_secret(&ct, &s, &d, &p2, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_shared_secret(&ct, &s2, &d2, &p, &drbg, c, e));
        SB_TEST_ASSERT_EQUAL(s, s2);

        SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&ct, &p3, &d, &p2, &drbg,
                                                    c, e));
        SB_TEST_ASSERT_SUCCESS(sb_sw_point_multiply(&ct, &p4, &d2, &p, &drbg,
                                                    c, e));
        SB_TEST_ASSERT_EQUAL(p3, p4);

        SB_TEST_ASSERT_SUCCESS(sb_sw_compress_public_key(&ct, &x, &sg, &p3,
                                                         c, e));
        SB_TEST_ASSERT_EQUAL(s, x);

        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                                TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2))
        );
        i++;
    } while (i < SB_TEST_RAND_COUNT);
    return 1;
}

// Test ECDH between random keys on P-256.
_Bool sb_test_shared_iter(void)
{
    return sb_test_shared_iter_c(SB_SW_CURVE_P256, SB_DATA_ENDIAN_LITTLE);
}

// Test ECDH between random keys on secp256k1.
_Bool sb_test_shared_iter_secp256k1(void)
{
    return sb_test_shared_iter_c(SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_BIG);
}

// Test signing random messages with random private keys, and verifying these
// signatures. Among the sign_iter, shared_iter, and invert_iter tests, every
// function that takes an optional drbg input is called with a drbg.
static _Bool sb_test_sign_iter_c(const sb_sw_curve_id_t c,
                                 const sb_data_endian_t e)
{
    sb_sw_private_t d;
    sb_sw_public_t p;
    sb_sw_signature_t s;
    sb_sw_context_t ct;
    sb_sw_message_digest_t m;
    size_t i = 0;

    sb_hmac_drbg_state_t drbg;
    NULL_DRBG_INIT(&drbg);
    do {
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_generate_private_key(&ct, &d, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_compute_public_key(&ct, &p, &d, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_generate_additional_dummy
                                   (&drbg, m.bytes, sizeof(m.bytes)));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_sign_message_digest(&ct, &s, &d, &m, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_verify_signature(&ct, &s, &p, &m, &drbg, c, e));
        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                                TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2))
        );
        i++;
    } while (i < SB_TEST_RAND_COUNT);
    return 1;
}

// Test signing random messages on P-256.
_Bool sb_test_sign_iter(void)
{
    return sb_test_sign_iter_c(SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);
}

// Test signing random messages on secp256k1.
_Bool sb_test_sign_iter_secp256k1(void)
{
    return sb_test_sign_iter_c(SB_SW_CURVE_SECP256K1, SB_DATA_ENDIAN_LITTLE);
}

#endif
