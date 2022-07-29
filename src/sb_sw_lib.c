/** @file sb_sw_lib.c
 *  @brief operations on short Weierstrass elliptic curves
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
#include "sb_sw_lib.h"
#include "sb_sw_curves.h"
#include "sb_hmac_drbg.h"
#include "sb_hkdf.h"
#include "sb_error.h"
#include "sb_test_cavp.h"
#include "sb_time.h"

#include <stddef.h>
#include <string.h>

// Used for point addition and conjugate addition
#define C_X1(ct) (&(ct)->param_use.curve_arith.p[0].x)
#define C_Y1(ct) (&(ct)->param_use.curve_arith.p[0].y)
#define C_X2(ct) (&(ct)->param_use.curve_arith.p[1].x)
#define C_Y2(ct) (&(ct)->param_use.curve_arith.p[1].y)
#define C_T5(ct) (&(ct)->param_use.curve_temporaries.t[0])
#define C_T6(ct) (&(ct)->param_use.curve_temporaries.t[1])
#define C_T7(ct) (&(ct)->param_use.curve_temporaries.t[2])
#define C_T8(ct) (&(ct)->param_use.curve_temporaries.t[3])

#define MULT_STATE(ct) (&(ct)->param_use.saved_state)

// The scalar used for point multiplication
#define MULT_K(ct) (&(ct)->params.k)

// The initial Z value, and the current Z coordinate in multiplication-addition
#define MULT_Z(ct) (&(ct)->params.z)

// Candidate to be tested during Z generation
#define MULT_Z2(ct) (&(ct)->param_gen.z2)

// The point to be multiplied, for shared secret generation and signature
// verification
#define MULT_POINT(ct) (&(ct)->param_use.mult.point)
#define MULT_POINT_X(ct) (&(ct)->param_use.mult.point.x)
#define MULT_POINT_Y(ct) (&(ct)->param_use.mult.point.y)

// The message to be signed as a scalar
#define SIGN_MESSAGE(ct) (&(ct)->param_use.sign.message)

// The private key used in signing as a scalar (K is the signature k)
#define SIGN_PRIVATE(ct) (&(ct)->param_use.sign.priv)

// The scalar to multiply the base point by in signature verification
#define MULT_ADD_KG(ct) (&(ct)->param_use.verify.late.kg)

// Stores P + G in signature verification
#define MULT_ADD_PG(ct) (&(ct)->param_use.verify.late.pg)

// The message to be verified as a scalar
#define VERIFY_MESSAGE(ct) (&(ct)->param_use.verify.early.message)

// The two working components of the signature, R and S
#define VERIFY_QS(ct) (&(ct)->param_use.verify.early.qs)
#define VERIFY_QR(ct) (&(ct)->param_use.verify.common.qr)

// Helper to fetch a curve given its curve_id
static sb_error_t sb_sw_curve_from_id(const sb_sw_curve_t** const s,
                                      sb_sw_curve_id_t const curve)
{
    switch (curve) {
#if SB_SW_P256_SUPPORT
        case SB_SW_CURVE_P256: {
            *s = &SB_CURVE_P256;
            return 0;
        }
#endif
#if SB_SW_SECP256K1_SUPPORT
        case SB_SW_CURVE_SECP256K1: {
            *s = &SB_CURVE_SECP256K1;
            return 0;
        }
#endif
#ifdef SB_TEST
        case SB_SW_CURVE_INVALID:
            break;
#endif
    }
    // Huh?
    *s = NULL;
    return SB_ERROR_CURVE_INVALID;
}

// All multiplication in Sweet B takes place using Montgomery multiplication
// MM(x, y) = x * y * R^-1 mod M where R = 2^SB_FE_BITS
// This has the nice property that MM(x * R, y * R) = x * y * R
// which means that sequences of operations can be chained together

// The inner loop of the Montgomery ladder takes place with coordinates that have been
// pre-multiplied by R. Point addition involves no constants, only additions, subtractions,
// and multiplications (and squarings). As such, the factor of R in coordinates is maintained
// throughout: mont_mult(a * R, b * R) = (a * b) * R, a * R + b * R = (a + b) * R, etc.
// For simplicity, the factor R will be ignored in the following comments.

// Initial point doubling: compute 2P in Jacobian coordinates from P in
// affine coordinates.

// Algorithm 23 from Rivain 2011, modified slightly

// Input:  P = (x2, y2) in affine coordinates
// Output: (x1, y1) = P', (x2, y2) = 2P in co-Z with t5 = Z = 2 * y2
// Cost:   6MM + 11A
static void sb_sw_point_initial_double(sb_sw_context_t c[static const 1],
                                       const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_double(C_T5(c), C_Y2(c), s->p); // t5 = Z
    sb_fe_mont_square(C_Y1(c), C_X2(c), s->p); // t2 = x^2
    sb_fe_mod_sub(C_Y1(c), C_Y1(c), s->minus_a_r_over_three,
                  s->p); // t2 = x^2 + a / 3
    sb_fe_mod_double(C_X1(c), C_Y1(c), s->p); // t1 = 2 * (x^2 + a / 3)
    sb_fe_mod_add(C_Y1(c), C_Y1(c), C_X1(c),
                  s->p); // t2 = (3 * x^2 + a) = B

    sb_fe_mont_square(C_T6(c), C_Y2(c), s->p); // t6 = y^2
    sb_fe_mod_double(C_Y2(c), C_T6(c), s->p); // t4 = 2 * y^2
    sb_fe_mod_double(C_T6(c), C_Y2(c), s->p); // t6 = 4 * y^2
    sb_fe_mont_mult(C_X1(c), C_X2(c), C_T6(c),
                    s->p); // t1 = 4 * x * y^2 = A

    sb_fe_mont_square(C_X2(c), C_Y1(c),
                      s->p); // t3 = B^2

    sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c), s->p); // t2 = B^2 - A
    sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c),
                  s->p); // x2 = B^2 - 2 * A = X2

    sb_fe_mod_sub(C_T6(c), C_X1(c), C_X2(c), s->p); // t6 = A - X2
    sb_fe_mont_mult(C_T7(c), C_Y1(c), C_T6(c),
                    s->p); // t7 = B * (A - X2)

    sb_fe_mont_square(C_Y1(c), C_Y2(c),
                      s->p); // t2 = (2 * y^2)^2 = 4 * y^4
    sb_fe_mod_double(C_Y1(c), C_Y1(c), s->p); // Y1 = 8 * y^4 = Z^3 * y
    sb_fe_mod_sub(C_Y2(c), C_T7(c), C_Y1(c),
                  s->p); // Y2 = B * (A - X2) - Y1
}

// Co-Z point addition with update:
// Input: P = (x1, y1), Q = (x2, y2) in co-Z, with x2 - x1 in t6
// Output: P + Q = (x3, y3) in (x1, y1), P = (x1', y1') in (x2, y2)
//         B + C = t5 with Z' = Z * (x2 - x1)
//     or: P = P + Q, Q = P'
// Uses:   t5, t6, t7; leaves t8 unmodified (used by conjugate addition and Z recovery)
// Cost:   6MM + 6A
static void sb_sw_point_co_z_add_update_zup(sb_sw_context_t c[static const 1],
                                            const sb_sw_curve_t s[static const 1])
{
    sb_fe_mont_square(C_T5(c), C_T6(c),
                      s->p); // t5 = (x2 - x1)^2 = (Z' / Z)^2 = A
    sb_fe_mont_mult(C_T6(c), C_X2(c), C_T5(c), s->p); // t6 = x2 * A = C
    sb_fe_mont_mult(C_X2(c), C_X1(c), C_T5(c), s->p); // t3 = x1 * A = B = x1'
    sb_fe_mod_sub(C_T7(c), C_Y2(c), C_Y1(c), s->p); // t7 = y2 - y1
    sb_fe_mod_add(C_T5(c), C_X2(c), C_T6(c), s->p); // t5 = B + C
    sb_fe_mod_sub(C_T6(c), C_T6(c), C_X2(c),
                  s->p); // t6 = C - B = (x2 - x1)^3 = (Z' / Z)^3
    sb_fe_mont_mult(C_Y2(c), C_Y1(c), C_T6(c),
                    s->p); // y1' = y1 * (Z' / Z)^3 = E
    sb_fe_mont_square(C_X1(c), C_T7(c), s->p); // t1 = (y2 - y1)^2 = D
    sb_fe_mod_sub(C_X1(c), C_X1(c), C_T5(c), s->p); // x3 = D - B - C
    sb_fe_mod_sub(C_T6(c), C_X2(c), C_X1(c), s->p); // t6 = B - x3
    sb_fe_mont_mult(C_Y1(c), C_T7(c), C_T6(c),
                    s->p); // t4 = (y2 - y1) * (B - x3)
    sb_fe_mod_sub(C_Y1(c), C_Y1(c), C_Y2(c),
                  s->p); // y3 = (y2 - y1) * (B - x3) - E
}

// Co-Z addition with update, with Z-update computation
// Sets t6 to x2 - x1 before calling sb_sw_point_co_z_add_update_zup
// Cost: 6MM + 7A
static inline void
sb_sw_point_co_z_add_update(sb_sw_context_t c[static const 1],
                            const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_sub(C_T6(c), C_X2(c), C_X1(c), s->p); // t6 = x2 - x1 = Z' / Z
    sb_sw_point_co_z_add_update_zup(c, s);
}

// Co-Z conjugate addition with update, with Z-update computation
// Input:  P = (x1, y1), Q = (x2, y2) in co-Z, with x2 - x1 in t6
// Output: P + Q = (x3, y3) in (x1, y1), P - Q = in (x2, y2), P' in (t6, t7)
//         with Z' = Z * (x2 - x1)
//     or: P = P + Q, Q = P - Q
// Uses:   t5, t6, t7, t8
// Cost:   8MM + 11A (6MM + 7A for addition-with-update + 2MM + 4A)
static void sb_sw_point_co_z_conj_add(sb_sw_context_t c[static const 1],
                                      const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_add(C_T8(c), C_Y1(c), C_Y2(c), s->p); // t8 = y1 + y2

    sb_sw_point_co_z_add_update(c, s); // t5 = B + C

    *C_T6(c) = *C_X2(c);
    *C_T7(c) = *C_Y2(c);

    sb_fe_mont_square(C_X2(c), C_T8(c), s->p); // t6 = (y1 + y2)^2 = F
    sb_fe_mod_sub(C_X2(c), C_X2(c), C_T5(c), s->p); // t6 = F - (B + C) = x3'

    sb_fe_mod_sub(C_T5(c), C_X2(c), C_T6(c), s->p); // t5 = x3' - B
    sb_fe_mont_mult(C_Y2(c), C_T8(c), C_T5(c),
                    s->p); // t2 = (y2 + y1) * (x3' - B)
    sb_fe_mod_sub(C_Y2(c), C_Y2(c), C_T7(c),
                  s->p); // y3' = (y2 + y1) * (x3' - B) - E
}

// Regularize the bit count of the scalar by adding CURVE_N or 2 * CURVE_N
// The resulting scalar will have P256_BITS + 1 bits, with the highest bit set
// This enables the Montgomery ladder to start at (1P, 2P) instead of (0P, 1P).
// The resulting scalar k is always >= N + R (where R is 2^256 mod N) and
// < 2N + R.
// To see how this works, consider an input scalar of R: the first addition
// produces N + (2^256 - N) = 2^256 and overflows; therefore the resulting
// scalar will be N + R, and this is the lowest scalar that produces
// overflow on the first addition. Now consider an input scalar of R - 1:
// the first addition produces N + (2^256 - N - 1) = 2^256 - 1 which does
// not overflow; hence a second addition is necessary. This is the largest
// scalar which requires two additions.

static void sb_sw_regularize_scalar(sb_fe_t scalar[static const 1],
                                    sb_sw_context_t c[static const 1],
                                    const sb_sw_curve_t s[static const 1])
{
    const sb_word_t c_1 = sb_fe_add(C_T5(c), scalar, &s->n->p);
    sb_fe_add(scalar, C_T5(c), &s->n->p);
    sb_fe_ctswap(c_1, scalar, C_T5(c));
}

static void
sb_sw_point_mult_start(sb_sw_context_t m[static const 1],
                       const sb_sw_curve_t curve[static const 1])
{
    // Input scalars MUST always be checked for validity
    // (k is reduced and nonzero mod N).

    sb_sw_context_saved_state_t state = *MULT_STATE(m);

    // If the input point is (0, ±√𝐵), the scalar will be halved
    // and the point 2 * (0, ±√𝐵) will be substituted in instead.

    // is_zero is not persisted in the state because restoration of
    // the original scalar is only needed for signing, which involves
    // a multiplication by G (and thus is_zero is always 0).
    const sb_word_t is_zero = sb_fe_equal(MULT_POINT_X(m), &curve->p->p);

    // Because the input point is already in Montgomery domain, the sign
    // can't be computed directly from the Y coordinate in MULT_POINT_Y.
    sb_fe_mont_reduce(C_Y1(m), MULT_POINT_Y(m), curve->p);
    const sb_word_t zero_sign = sb_fe_test_bit(C_Y1(m), 0);

    // Copy 2 * (0, √𝐵) into (X1, Y1)
    *C_X1(m) = curve->dz_r.x;
    *C_Y1(m) = curve->dz_r.y;

    // (X1, Y2) = -2 * (0, √𝐵)
    sb_fe_mod_negate(C_Y2(m), C_Y1(m), curve->p);

    // Swap in the appropriate point based on the "sign" of the input point.
    sb_fe_ctswap(zero_sign, C_Y1(m), C_Y2(m));

    // Halve the input scalar into t5
    sb_fe_mod_halve(C_T5(m), MULT_K(m), C_T6(m), curve->n);

    // Swap in the halved scalar and doubled point based on is_zero
    sb_fe_ctswap(is_zero, MULT_K(m), C_T5(m));
    sb_fe_ctswap(is_zero, MULT_POINT_X(m), C_X1(m));
    sb_fe_ctswap(is_zero, MULT_POINT_Y(m), C_Y1(m));

    // If the top bit of the scalar is set, invert the scalar and the input
    // point. This ensures that the scalar -2, which would otherwise be
    // exceptional in our ladder, is treated as the scalar 2. The
    // corresponding inversion will be performed to the output point at the
    // end of the ladder. Note that this assumes a 256-bit field order;
    // this assumption is also made in sb_sw_regularize_scalar. All
    // inversions are computed unconditionally, and the inv_k flag is used
    // for constant-time swaps.
    state.inv_k = sb_fe_test_bit(MULT_K(m), SB_FE_BITS - 1);

    sb_fe_mod_negate(C_T5(m), MULT_K(m), curve->n);
    sb_fe_ctswap(state.inv_k, C_T5(m), MULT_K(m));

    // The scalar 1 will be handled by allowing the ladder to produce the
    // exceptional output (0, 0), then adding in the original point X and Y
    // values to produce P. This addition is performed unconditionally, and the
    // k_one flag is used only for constant-time swaps. Because of the scalar
    // inversion above, -1 will be handled as 1 during the ladder, and P will
    // be inverted to produce -P.
    state.k_one = sb_fe_equal(MULT_K(m), &SB_FE_ONE);

    sb_sw_regularize_scalar(MULT_K(m), m, curve);

    // Throughout the ladder, (x1, y1) is (X0 * R, Y0 * R)
    // (x2, y2) is (X1 * R, Y1 * R)
    // This enables montgomery multiplies to be used in the ladder without
    // explicit multiplies by R^2 mod P
    // It is assumed that the input point has been pre-multiplied by R. In
    // the case of the base point of the curve, it is stored this way in the
    // curve constant. In the case of ECDH, the point X and Y values will be
    // converted to the Montgomery domain in the wrapper for this routine.

    *C_X2(m) = *MULT_POINT_X(m);
    *C_Y2(m) = *MULT_POINT_Y(m);

    sb_sw_point_initial_double(m, curve);

    // The following applies a Z update of iz * R^-1.

    sb_fe_mont_square(C_T7(m), MULT_Z(m), curve->p); // t7 = z^2
    sb_fe_mont_mult(C_T6(m), MULT_Z(m), C_T7(m), curve->p); // t6 = z^3

    *C_T5(m) = *C_X1(m);
    sb_fe_mont_mult(C_X1(m), C_T5(m), C_T7(m), curve->p); // x z^2
    *C_T5(m) = *C_Y1(m);
    sb_fe_mont_mult(C_Y1(m), C_T5(m), C_T6(m), curve->p); // y z^3
    *C_T5(m) = *C_X2(m);
    sb_fe_mont_mult(C_X2(m), C_T5(m), C_T7(m), curve->p); // x z^2
    *C_T5(m) = *C_Y2(m);
    sb_fe_mont_mult(C_Y2(m), C_T5(m), C_T6(m), curve->p); // y z^3

    state.i = SB_FE_BITS - 1;
    state.stage = SB_SW_POINT_MULT_OP_STAGE_LADDER;

    *MULT_STATE(m) = state;
}

#define SB_SW_POINT_ITERATIONS 16

static _Bool
sb_sw_point_mult_continue(sb_sw_context_t m[static const 1],
                          const sb_sw_curve_t curve[static const 1])
{
    sb_sw_context_saved_state_t state = *MULT_STATE(m);

    // (x1 * R^-1, y1 * R^-1) = R0, (x2 * R^-1, y2 * R^-1) = R1
    // R1 - R0 = P' for some Z

    // To show that the ladder is complete for scalars ∉ {-2, -1, 0, 1}, let:
    // P  = p * G
    // R1 = 2 * p * G
    // R0 = p * G
    // It is easy to see that in a prime-order group, neither R1 nor R0 is
    // the point at infinity at the beginning of the algorithm assuming nonzero p.
    // In other words, every point on the curve is a generator.

    // Through the ladder, at the end of each ladder step, we have:
    // R0 = k[256..i] * P
    // R1 = R0 + P
    // where k[256..i] is the 256th through i_th bit of `k` inclusive
    // The beginning of the loop is the end of the first ladder step (i = 256).

    // Each ladder step computes the sum of R0 and R1, and one point doubling.
    // The point doubling formula does not have exceptional cases, so we must
    // consider point additions by zero and inadvertent point doublings.
    // (Additions of -P and P would produce zero, which reduces to the case
    // of addition by zero.) Point doublings do not occur simply because R0 +
    // (R0 + P) is never a doubling operation.

    // R0 = k[256..i] * P is the point at infinity if k[256..i] is zero.
    // k[256] is 1 and N is 256 bits long. Therefore, k[256..i] is nonzero
    // and less than N for all i > 1.
    // It remains to consider the case of k[256..1] = N and
    // k[256..0] = 2N. If k[256..1] is N, then k[256..0] is 2N or 2N + 1.
    // Because the original input scalar was reduced, this only occurs with
    // an input scalar of 0 or 1.

    // R1 = (k[256..i] + 1) * P is zero if k[256..i] + 1 is zero.
    // N is 256 bits long. For i > 1, k[256..i] is at most 255 bits long and therefore
    // less than N - 1. It remains to consider k[256..1] = N - 1 and k[256..0] = 2N - 1.
    // If k[256..1] is N - 1, then k[256..0] is 2N - 2 or 2N - 1.
    // Because the input scalar was reduced, this only occurs with an input
    // scalar of -2 or -1.

    // The following intermediaries are generated:
    // (2 * k[256..i] + 1) * P, P, and -P

    // Because the order of the group is prime, it is easy to see that
    // k[256..i] * P = 0 iff k[256..i] is 0 for nonzero p.
    // What about (2 * k[256..i] + 1) * P?
    // 2 * k[256..i] + 1 must be zero.
    // For i > 2, 2 * k[256..i] is at most 255 bits long and thus
    // less than N - 1. It remains to consider 2 * k[256..2] = N - 1,
    // 2 * k[256..1] = N - 1, and 2 * k[256..0] = N - 1.

    // If 2 * k[256..2] = N - 1, then k[256..2] = (N - 1) / 2.
    // k[256..1] is then N - 1 or N, and k[256..0] is 2N - 2, 2N - 1, N, or N + 1.
    // Thus, this occurs only if k ∈ { -2, -1, 0, 1 }.

    // If 2 * k[256..1] = N - 1, then k[256..1] is (N - 1) / 2.
    // k[256..0] is then N - 1 or N, which only occurs if k ∈ { -1, 0 }.

    // Thus, for reduced inputs ∉ {-2, -1, 0, 1} the Montgomery ladder
    // is non-exceptional for our short Weierstrass curves.

    // Because of the conditional inversion of the scalar at the beginning of
    // this routine, the inputs -2 and -1 are treated as 2 and 1,
    // respectively. As 1 is still an exceptional input, the set of remaining
    // exceptional cases is {-1, 0, 1} mod N. The case of -1 and 1 will be
    // handled after the ladder produces the point at infinity through a
    // series of unconditional additions and constant-time swaps.

    // 14MM + 18A per bit
    // c.f. Table 1 in Rivain 2011 showing 9M + 5S + 18A

    switch (state.stage) {
        case SB_SW_POINT_MULT_OP_STAGE_LADDER: {
            for (sb_bitcount_t ops = 0; state.i > 0 &&
                                        ops < SB_SW_POINT_ITERATIONS;
                 ops++, state.i--) {
                const sb_word_t b = sb_fe_test_bit(MULT_K(m), state.i);

                // if swap is 0: (x2, y2) = R0; (x1, y1) = R1
                // if swap is 1: (x2, y2) = R1; (x1, y1) = R0

                // swap iff bit is set:
                // (x1, y1) = R_b; (x2, y2) = R_{1-b}
                state.swap ^= b;
                sb_fe_ctswap(state.swap, C_X1(m), C_X2(m));
                sb_fe_ctswap(state.swap, C_Y1(m), C_Y2(m));
                state.swap = b;

                // our scalar 'k' is a 257-bit integer
                // R0 = k[256..(i+1)] * P
                // at the beginning of the loop, when i is 255:
                // R0 = k[256..256] * P = 1 * P
                // R1 = R0 + P = (k[256..(i+1)] + 1) * P


                // When k[i] is 0:
                // (x1, y1) = k[256..(i+1)] * P
                // (x2, y2) = (k[256..(i+1)] + 1) * P

                // When k[i] is 1:
                // (x1, y1) = (k[256..(i+1)] + 1) * P
                // (x2, y2) = k[256..(i+1)] * P

                // R_b = R_b + R_{1-b}; R_{1-b} = R_{b} - R{1-b}
                sb_sw_point_co_z_conj_add(m, curve); // 6MM + 7A

                // (x1, y1) = (2 * k[256..(i+1)] + 1 ) * P

                // if k[i] is 0:
                // (x2, y2) = -1 * P

                // if k[i] is 1:
                // (x2, y2) = 1 * P

                // R_b = R_b + R_{1-b}; R_{1-b} = R_b'
                sb_sw_point_co_z_add_update(m, curve); // 8MM + 11A

                // if k[i] is 0:
                // (x1, y1) is 2 * k[256..(i+1)] * P = k[256..i] * P
                // (x2, y2) is (2 * k[256..(i+1)] + 1 ) * P = (k[256..i] + 1) * P

                // if k[i] is 1:
                // (x1, y1) is (2 * k[256..(i+1)] + 2) * P = (k[256..i] + 1) * P
                // (x2, y2) is (2 * k[256..(i+1)] + 1 ) * P = k[256..i] * P

                // R_swap is k[256..i] * P
                // R_!swap is (k[256..i] + 1) * P
            }

            // If the above loop has terminated due to i being equal to zero,
            // move on to the next stage before yielding.
            if (state.i == 0) {
                state.stage = SB_SW_POINT_MULT_OP_STAGE_INV_Z;
            }

            *MULT_STATE(m) = state;
            return 0;
        }
        case SB_SW_POINT_MULT_OP_STAGE_INV_Z: {
            const sb_word_t b = sb_fe_test_bit(MULT_K(m), 0);

            // (x1, y1) = R0; (x2, y2) = R1

            // swap iff bit is set:
            state.swap ^= b;
            sb_fe_ctswap(state.swap, C_X1(m), C_X2(m));
            sb_fe_ctswap(state.swap, C_Y1(m), C_Y2(m));

            // (x1, y1) = R_b; (x2, y2) = R_{1-b}

            // here the logical meaning of the registers swaps!
            sb_sw_point_co_z_conj_add(m, curve);
            // (x1, y1) = R_{1-b}, (x2, y2) = R_b

            // if b is 1, swap the registers
            sb_fe_ctswap(b, C_X1(m), C_X2(m));
            sb_fe_ctswap(b, C_Y1(m), C_Y2(m));
            // (x1, y1) = R1; (x2, y2) = R0

            // Compute final Z^-1
            sb_fe_mod_sub(C_T8(m), C_X1(m), C_X2(m), curve->p); // X1 - X0

            // if b is 1, swap the registers back
            sb_fe_ctswap(b, C_X1(m), C_X2(m));
            sb_fe_ctswap(b, C_Y1(m), C_Y2(m));
            // (x1, y1) = R_{1-b}, (x2, y2) = R_b

            sb_fe_mont_mult(C_T5(m), C_T8(m), C_Y2(m), curve->p);
            // t5 = Y_b * (X_1 - X_0)

            sb_fe_mont_mult(C_T8(m), C_T5(m), MULT_POINT_X(m), curve->p);
            // t8 = t5 * x_P = x_P * Y_b * (X_1 - X_0)

            sb_fe_mod_inv_r(C_T8(m), C_T5(m), C_T6(m), curve->p);
            // t8 = 1 / (x_P * Y_b * (X_1 - X_0))

            sb_fe_mont_mult(C_T5(m), C_T8(m), MULT_POINT_Y(m), curve->p);
            // t5 = yP / (x_P * Y_b * (X_1 - X_0))

            sb_fe_mont_mult(C_T8(m), C_T5(m), C_X2(m), curve->p);
            // t8 = (X_b * y_P) / (x_P * Y_b * (X_1 - X_0))
            // = final Z^-1

            // (x1, y1) = R_{1-b}, (x2, y2) = R_b
            sb_sw_point_co_z_add_update(m, curve);
            // the logical meaning of the registers is reversed
            // (x1, y1) = R_b, (x2, y2) = R_{1-b}

            // if b is 0, swap the registers
            sb_fe_ctswap((b ^ (sb_word_t) 1), C_X1(m), C_X2(m));
            sb_fe_ctswap((b ^ (sb_word_t) 1), C_Y1(m), C_Y2(m));
            // (x1, y1) = R1; (x2, y2) = R0

            // t8 = Z^-1 * R
            // x2 = X0 * Z^2 * R
            // y2 = Y0 * Z^3 * R

            sb_fe_mont_square(C_T5(m), C_T8(m),
                              curve->p); // t5 = Z^-2 * R
            sb_fe_mont_mult(C_T6(m), C_T5(m), C_T8(m),
                            curve->p); // t6 = Z^-3 * R

            // Handle the exceptional cases of multiplies by -1 or 1 here. Because
            // the scalar has not been re-inverted yet, the value of MULT_K(m) will
            // be the scalar 1 if the original input scalar was -1.

            // Because a scalar of 1 produces an exception, the resulting X and Y
            // will be equal to P. Add the original point value to the result X and
            // Y, and swap it into the output X and Y if the scalar is 1.

            // The addition takes place before the Montgomery reduction because the
            // input point is in the Montgomery domain.

            // Apply the recovered Z to produce the X value of the output point, in the
            // Montgomery domain.
            sb_fe_mont_mult(C_T7(m), C_T5(m), C_X2(m),
                            curve->p); // t7 = X0 * Z^-2 * R

            // Add X_P and swap iff the scalar is 1.
            sb_fe_mod_add(C_X2(m), C_T7(m), MULT_POINT_X(m), curve->p);
            // x2 = t7 + x_P
            sb_fe_ctswap(state.k_one, C_T7(m), C_X2(m));

            sb_fe_mont_reduce(C_X1(m), C_T7(m),
                              curve->p); // Montgomery reduce to x1

            // Apply the recovered Z to produce the Y value of the output point, in the
            // Montgomery domain.
            sb_fe_mont_mult(C_T7(m), C_T6(m), C_Y2(m),
                            curve->p); // t7 = Y0 * Z^-3 * R

            // Add Y_P and swap iff the scalar is 1.
            sb_fe_mod_add(C_Y2(m), C_T7(m), MULT_POINT_Y(m), curve->p);
            // y2 = t7 + y_P
            sb_fe_ctswap(state.k_one, C_T7(m), C_Y2(m));

            sb_fe_mont_reduce(C_Y1(m), C_T7(m),
                              curve->p); // Montgomery reduce to y1

            // If the scalar was inverted, invert the output point. On a short
            // Weierstrass curve, -(X, Y) = (X, -Y).
            sb_fe_mod_negate(C_T5(m), C_Y1(m), curve->p);
            sb_fe_ctswap(state.inv_k, C_Y1(m), C_T5(m));

            sb_fe_sub(MULT_K(m), MULT_K(m),
                      &curve->n->p); // subtract off the overflow
            sb_fe_mod_reduce(MULT_K(m),
                             curve->n); // reduce to restore original scalar

            // And finally, if the scalar was inverted, re-invert it to restore the
            // original value.
            sb_fe_mod_negate(C_T5(m), MULT_K(m), curve->n);
            sb_fe_ctswap(state.inv_k, C_T5(m), MULT_K(m));

            // This operation is done.
            state.stage = SB_SW_POINT_MULT_OP_DONE;
            *MULT_STATE(m) = state;
            return 1;
        }
        default: {
            return state.stage == SB_SW_POINT_MULT_OP_DONE;
        }
    }
}

// Are we there yet?
static _Bool sb_sw_point_mult_is_finished(sb_sw_context_t m[static const 1])
{
    return MULT_STATE(m)->stage == SB_SW_POINT_MULT_OP_DONE;
}

// Multiplication-addition using Shamir's trick to produce k_1 * P + k_2 * Q

// sb_sw_point_mult_add_z_update computes the new Z and then performs co-Z
// point addition at a cost of 7MM + 7A
static void sb_sw_point_mult_add_z_update(sb_sw_context_t q[static const 1],
                                          const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_sub(C_T6(q), C_X2(q), C_X1(q), s->p); // t6 = x2 - x1 = Z' / Z
    sb_fe_mont_mult(C_T5(q), C_T6(q), MULT_Z(q), s->p); // updated Z
    *MULT_Z(q) = *C_T5(q);

    sb_sw_point_co_z_add_update_zup(q, s);
}

// sb_sw_point_mult_add_apply_z applies a Z value to the selected point
// (H, P + H, G + H, or P + G + H) at a cost of 4MM
static void sb_sw_point_mult_add_apply_z(sb_sw_context_t q[static const 1],
                                         const sb_sw_curve_t s[static const 1])
{
    sb_fe_mont_square(C_T6(q), MULT_Z(q), s->p); // Z^2

    sb_fe_mont_mult(C_T7(q), C_X2(q), C_T6(q), s->p);
    *C_X2(q) = *C_T7(q);

    sb_fe_mont_mult(C_T7(q), C_T6(q), MULT_Z(q), s->p); // Z^3
    sb_fe_mont_mult(C_T6(q), C_Y2(q), C_T7(q), s->p);
    *C_Y2(q) = *C_T6(q);
}

// sb_sw_point_mult_add_select selects the point to conjugate-add to the
// running total based on the bits of the given input scalars
static void sb_sw_point_mult_add_select(const sb_word_t bp, const sb_word_t bg,
                                        sb_sw_context_t q[static const 1],
                                        const sb_sw_curve_t s[static const 1])
{
    // select a point S for conjugate addition with R
    // if bp = 0 and bg = 0, select h
    // if bp = 0 and bg = 1, select g + h
    // if bp = 1 and bg = 0, select p + h
    // if bp = 1 and bg = 1, select p + g + h
    *C_X2(q) = s->h_r.x;
    *C_Y2(q) = s->h_r.y;

    *C_T5(q) = s->g_h_r.x;
    *C_T6(q) = s->g_h_r.y;
    sb_fe_ctswap(bg, C_X2(q), C_T5(q));
    sb_fe_ctswap(bg, C_Y2(q), C_T6(q));

    *C_T5(q) = *MULT_POINT_X(q);
    *C_T6(q) = *MULT_POINT_Y(q);
    sb_fe_ctswap(bp, C_X2(q), C_T5(q));
    sb_fe_ctswap(bp, C_Y2(q), C_T6(q));

    *C_T5(q) = MULT_ADD_PG(q)->x;
    *C_T6(q) = MULT_ADD_PG(q)->y;
    sb_fe_ctswap(bp & bg, C_X2(q), C_T5(q));
    sb_fe_ctswap(bp & bg, C_Y2(q), C_T6(q));

    sb_sw_point_mult_add_apply_z(q, s);
}

// Signature verification uses a regular double-and-add algorithm with Shamir's
// trick for dual scalar-basepoint multiplication. Because adding O (the
// point at infinity) is an exceptional case in the standard formulae for
// point addition on short Weierstrass curves, each iteration adds an
// additional point H. The initial value of the point accumulator register is H,
// and at the end of the loop, (2^257 - 1) * H has been added, producing
// k_p * P + k_g * G + (2^257 - 1) * H. To correct for this, one could
// subtract the extra multiple of H at the end of the algorithm, but instead
// H has been chosen so that we can easily adjust k_g before the
// multiplication instead. Let H be (2^257 - 1)^-1 * G. Then compute:
//   k_p * P + (k_g - 1) * G + (2^257 - 1) * H
// = k_p * P + (k_g - 1) * G + (2^257 - 1) * (2^257 - 1)^-1 * G
// = k_p * P + (k_g - 1) * G + G
// = k_p * P + k_g * G

// The algorithm is as follows:

// Given inputs k_p, P, k_g on some curve with base point G, and let H as
// above, with G + H precomputed

// 1. Compute P + H and P + G + H

// Let S(b_p, b_g) be:         H if b_p == 0 && b_g == 0
//                         P + H if b_p == 1 && b_g == 0
//                         G + H if b_p == 0 && b_g == 1
//                     P + G + H if b_p == 1 && b_g == 1

// 2. k_g := k_g - 1
// 3. R := H
// 4. R := 2 * R
// 5. R := R + S(k_p_255, k_g_255)
// 6. for i from 254 downto 0:
//    6.1. R' := R + S(k_p_i, k_g_i)
//    6.2. R  := R + R'
// 7. return R

// Note that this algorithm is NOT exception-free! It is assumed that
// exceptions do not matter in practice here, because they occur only in one
// of the following situations:

// P = +/- H
// P = +/- G
// P = +/- (G + H)
// k_g[255 .. n] * G + (2^257 - 1)[255 .. n] * H = +/- k_p[255 .. n] * P

// It's possible to express any of these equivalences in the following form:

// p * G = P for some p

// In other words, exceptions during signature verification imply that the
// private key of the message signer can be deduced with simple algebra.
// While it might be preferable to have a signature verification algorithm
// that can correctly verify such signatures, in this case it would
// complicate the implementation greatly. Furthermore, it could also be
// argued that refusing to verify such signatures is, in fact, the preferable
// choice, as any signature created with this private key might be forged.

// Produces kp * P + kg * G in (x1, y1) with Z * R in Z
static _Bool sb_sw_point_mult_add_z_continue
    (sb_sw_context_t q[static const 1],
     const sb_sw_curve_t s[static const 1])
{
    sb_sw_context_saved_state_t state = *MULT_STATE(q);

    switch (state.stage) {
        case SB_SW_VERIFY_OP_STAGE_INV_Z: {
            // Subtract one from kg to account for the addition of (2^257 - 1) * H = G
            sb_fe_sub(MULT_ADD_KG(q), MULT_ADD_KG(q), &SB_FE_ONE);

            // multiply (x, y) of P by R
            sb_fe_mont_convert(C_X1(q), MULT_POINT_X(q), s->p);
            *MULT_POINT_X(q) = *C_X1(q);
            sb_fe_mont_convert(C_Y1(q), MULT_POINT_Y(q), s->p);
            *MULT_POINT_Y(q) = *C_Y1(q);

            *C_X2(q) = s->h_r.x;
            *C_Y2(q) = s->h_r.y;

            // Save initial Z in T8 until it can be applied
            *C_T8(q) = *MULT_Z(q);

            // P and H are in affine coordinates, so our current Z is one (R in
            // Montgomery domain)
            *MULT_Z(q) = s->p->r_mod_p;

            // (x1, x2) = P + H; (x2, y2) = P'
            sb_sw_point_mult_add_z_update(q, s);

            // Apply Z to G before co-Z addition of (P + H) and G
            *C_X2(q) = s->g_r.x;
            *C_Y2(q) = s->g_r.y;
            sb_sw_point_mult_add_apply_z(q, s);

            // (x1, x2) = P + G + H; (x2, y2) = P + H
            sb_sw_point_mult_add_z_update(q, s);

            // Invert Z and multiply so that P + H and P + G + H are in affine
            // coordinates
            *C_T5(q) = *MULT_Z(q); // t5 = Z * R
            sb_fe_mod_inv_r(C_T5(q), C_T6(q), C_T7(q), s->p); // t5 = Z^-1 * R
            sb_fe_mont_square(C_T6(q), C_T5(q), s->p); // t6 = Z^-2 * R
            sb_fe_mont_mult(C_T7(q), C_T5(q), C_T6(q), s->p); // t7 = Z^-3 * R

            // Apply Z to P + H
            sb_fe_mont_mult(MULT_POINT_X(q), C_X2(q), C_T6(q), s->p);
            sb_fe_mont_mult(MULT_POINT_Y(q), C_Y2(q), C_T7(q), s->p);

            // Apply Z to P + G + H
            sb_fe_mont_mult(&MULT_ADD_PG(q)->x, C_X1(q), C_T6(q), s->p);
            sb_fe_mont_mult(&MULT_ADD_PG(q)->y, C_Y1(q), C_T7(q), s->p);

            // Computation begins with R = H. If bit 255 of kp and kpg are both 0,
            // this would lead to a point doubling!
            // Avoid the inadvertent doubling in the first bit, so that the regular
            // ladder can start at 2 * H + S

            *C_X2(q) = s->h_r.x;
            *C_Y2(q) = s->h_r.y;

            sb_sw_point_initial_double(q, s);
            // 2 * H is now in (x2, y2); Z is in t5

            // apply initial Z
            *MULT_Z(q) = *C_T8(q);
            sb_sw_point_mult_add_apply_z(q, s);

            // z coordinate of (x2, y2) is now iz * t5
            sb_fe_mont_mult(C_T6(q), MULT_Z(q), C_T5(q), s->p);
            *MULT_Z(q) = *C_T6(q);

            // move 2 * H to (x1, y1)
            *C_X1(q) = *C_X2(q);
            *C_Y1(q) = *C_Y2(q);

            state.i = SB_FE_BITS - 1;
            state.stage = SB_SW_VERIFY_OP_STAGE_LADDER;
            *MULT_STATE(q) = state;
            return 0;
        }
        case SB_SW_VERIFY_OP_STAGE_LADDER: {
            // 14MM + 14A + 4MM co-Z update = 18MM + 14A per bit

            // The algorithm used here is regular and reuses the existing co-Z addition
            // operation. If you want a variable-time ladder, consider using
            // Algorithms 14 and 17 from Rivain 2011 instead.

            // Note that mixed Jacobian-affine doubling-addition can be done in 18MM.
            // Assuming a Hamming weight of ~128 on both scalars and 8MM doubling, the
            // expected performance of a variable-time Jacobian double-and-add
            // implementation would be (3/4 * 18MM) + (1/4 * 8MM) = 15.5MM/bit

            // Note that this algorithm may also not be SPA- or DPA-resistant, as H,
            // P + H, G + H, and P + G + H are stored and used in affine coordinates,
            // so the co-Z update of these variables might be detectable even with
            // Z blinding.

            // This loop goes from 255 down to 0, inclusive. When state.i
            // reaches 0 and is decremented, it wraps around to the most
            // positive sb_size_t, which is greater than or equal to SB_FE_BITS
            // (by quite a lot!).

            for (sb_bitcount_t ops = 0;
                 state.i < SB_FE_BITS && ops < SB_SW_POINT_ITERATIONS;
                 state.i--, ops++) {
                const sb_word_t bp = sb_fe_test_bit(MULT_K(q), state.i);
                const sb_word_t bg = sb_fe_test_bit(MULT_ADD_KG(q), state.i);

                sb_sw_point_mult_add_select(bp, bg, q, s);

                // (x1, y1) = (R + S), (x2, y2) = R'
                sb_sw_point_mult_add_z_update(q, s);

                // The initial point has already been doubled
                if (state.i < SB_FE_BITS - 1) {
                    // R := (R + S) + R = 2 * R + S
                    sb_sw_point_mult_add_z_update(q, s);
                }
            }

            // If the loop terminated because state.i was decremented from 0,
            // then state.i is the most positive sb_size_t, which is
            // >= SB_FE_BITS

            if (state.i >= SB_FE_BITS) {
                *C_T6(q) = *C_X1(q);
                sb_fe_mont_reduce(C_X1(q), C_T6(q), s->p);
                *C_T6(q) = *C_Y1(q);
                sb_fe_mont_reduce(C_Y1(q), C_T6(q), s->p);

                state.stage = SB_SW_VERIFY_OP_STAGE_TEST;
            }

            *MULT_STATE(q) = state;
            return 0;
        }
        default: {
            return 1;
        }
    }

}

// Given a point context with x in *C_X1(c), computes
// y^2 = x^3 + a * x + b in *C_Y1(c)
static void sb_sw_curve_y2(sb_sw_context_t c[static const 1],
                           const sb_sw_curve_t s[static const 1])
{
    sb_fe_mont_convert(C_T5(c), C_X1(c), s->p); // t5 = x * R
    sb_fe_mont_mult(C_T6(c), C_T5(c), C_X1(c), s->p); // t6 = x^2
    sb_fe_mod_sub(C_T6(c), C_T6(c), &s->minus_a, s->p); // t6 = x^2 + a
    sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c),
                    s->p); // y1 = (x^2 + a) * x * R * R^-1 = x^3 + a * x
    sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p); // y1 = y^2 = x^3 + a * x + b
}

// See SP 800-56A rev 3, section 5.6.2.3.4
// Note that the "full" test in 5.6.2.3.3 and the "partial" test in 5.6.2.3.4
// are equivalent on prime-order curves, since every point on the curve
// satisfies nQ = 0. The NSA's "Suite B Implementer's Guide to FIPS 186-3"
// document says as much in A.3.

// As implemented, all tests are performed regardless of whether any one test
// fails; in other words, tests are not short-circuited. This reduces the
// number of possible execution traces of the input.

// Note that this assumes reduced input, not quasi-reduced input! Special
// points of the form (0, Y) will be converted to quasi-reduced form in this
// routine.

static sb_word_t
sb_sw_point_validate(sb_sw_context_t c[static const 1],
                     const sb_sw_curve_t s[static const 1])
{
    sb_word_t r = 1;

    // 5.6.2.3.4 step 1: the point at infinity is not valid.
    // The only point with (X, 0) is the point at infinity. On the curve
    // P-256, the point (0, ±√B) is a valid point. The input point
    // representation (X, P) will be rejected by the step 2 test.
    r &= !sb_fe_equal(&MULT_POINT(c)->y, &SB_FE_ZERO);

    // 5.6.2.3.4 step 2: unreduced points are not valid.
    r &= (sb_fe_lt(&MULT_POINT(c)->x, &s->p->p) &
          sb_fe_lt(&MULT_POINT(c)->y, &s->p->p));

    // Valid Y values are now ensured to be quasi-reduced. Invalid Y values
    // have been flagged above, but must be quasi-reduced for the remainder
    // of the checks.
    sb_fe_mod_reduce(&MULT_POINT(c)->y, s->p);

    // If the input point has the form (0, Y) then the X value may be zero.
    // The modular quasi-reduction routine will change this to (P, Y).
    sb_fe_mod_reduce(&MULT_POINT(c)->x, s->p);

    // 5.6.2.3.4 step 3: verify y^2 = x^3 + ax + b
    sb_fe_mont_square(C_T5(c), &MULT_POINT(c)->y, s->p); // t5 = y^2 * R^-1
    sb_fe_mont_convert(C_Y2(c), C_T5(c), s->p); // y2 = y^2
    *C_X1(c) = MULT_POINT(c)->x;
    sb_sw_curve_y2(c, s);

    r &= sb_fe_equal(C_Y1(c), C_Y2(c));

    return r;
}

static sb_word_t
sb_sw_point_decompress(sb_sw_context_t c[static const 1],
                       const sb_word_t sign,
                       const sb_sw_curve_t s[static const 1])
{
    /* First validate the X coordinate of the point. */
    sb_word_t r = 1;

    // 5.6.2.3.4 step 2: unreduced points are not valid.
    r &= sb_fe_lt(&MULT_POINT(c)->x, &s->p->p);

    // The input X value may be 0 on some curves (such as NIST P-256).
    // The modular quasi-reduction routine will change this to P.
    sb_fe_mod_reduce(&MULT_POINT(c)->x, s->p);

    // Compute y^2 = x^3 + ax + b in C_Y1(c)
    *C_X1(c) = MULT_POINT(c)->x;
    sb_sw_curve_y2(c, s);

    // Compute the candidate square root
    r &= sb_fe_mod_sqrt(C_Y1(c), C_T5(c), C_T6(c), C_T7(c), C_T8(c), s->p);

    // If the "sign" bit does not match, invert the candidate square root
    const sb_word_t sign_mismatch = sb_fe_test_bit(C_Y1(c), 0) ^ sign;
    sb_fe_mod_negate(C_T5(c), C_Y1(c), s->p);
    sb_fe_ctswap(sign_mismatch, C_Y1(c), C_T5(c));

    MULT_POINT(c)->y = *C_Y1(c);

    return r;
}

// A scalar is valid if it is reduced and not equal to zero mod N.
static sb_word_t
sb_sw_scalar_validate(sb_fe_t k[static const 1],
                      const sb_sw_curve_t s[static const 1])
{
    sb_word_t r = 1;

    r &= sb_fe_lt(k, &s->n->p); // k < n
    sb_fe_mod_reduce(k, s->n); // after reduction, 0 is represented as n
    r &= !sb_fe_equal(k, &s->n->p); // k != 0

    return r;
}

// A z-coordinate is valid if it is reduced and not equal to zero mod P.
static sb_word_t
sb_sw_z_validate(sb_fe_t z[static const 1],
                 const sb_sw_curve_t s[static const 1])
{
    sb_word_t r = 1;

    r &= sb_fe_lt(z, &s->p->p); // k < p
    sb_fe_mod_reduce(z, s->p); // after reduction, 0 is represented as p
    r &= !sb_fe_equal(z, &s->p->p); // k != 0

    return r;
}

static void
sb_sw_sign_start(sb_sw_context_t g[static const 1],
                 const sb_sw_curve_t s[static const 1])
{
    *MULT_POINT(g) = s->g_r;

    *MULT_STATE(g) = (sb_sw_context_saved_state_t) {
        .operation = SB_SW_INCREMENTAL_OPERATION_SIGN_MESSAGE_DIGEST,
        .curve_id = s->id
    };

    sb_sw_point_mult_start(g, s);
}

static _Bool sb_sw_sign_is_finished(sb_sw_context_t g[static const 1])
{
    return MULT_STATE(g)->stage == SB_SW_SIGN_OP_STAGE_DONE;
}

// Places (r, s) into (x2, y2) when finished
static sb_error_t
sb_sw_sign_continue(sb_sw_context_t g[static const 1],
                    const sb_sw_curve_t s[static const 1],
                    _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;

    switch (MULT_STATE(g)->stage) {
        case SB_SW_SIGN_OP_STAGE_DONE: {
            *done = 1;
            return SB_SUCCESS;
        }
        case SB_SW_SIGN_OP_STAGE_INV: {
            sb_sw_context_saved_state_t state = *MULT_STATE(g);

            // This is used to quasi-reduce x1 modulo the curve N:
            *C_X2(g) = *C_X1(g);
            sb_fe_mod_reduce(C_X2(g), s->n);

            // If the ladder has produced (0, ±√B), then signing can't continue
            // and this is indicative of a DRBG failure.
            err |= SB_ERROR_IF(DRBG_FAILURE, sb_fe_equal(C_X2(g), &s->n->p));

            sb_fe_mont_convert(C_T7(g), MULT_K(g), s->n); // t7 = k * R
            sb_fe_mod_inv_r(C_T7(g), C_T5(g), C_T6(g), s->n); // t7 = k^-1 * R
            sb_fe_mont_convert(C_T6(g), SIGN_PRIVATE(g), s->n); // t6 = d_A * R
            sb_fe_mont_mult(C_T5(g), C_X2(g), C_T6(g), s->n); // t5 = r * d_A
            sb_fe_mod_add(C_T5(g), C_T5(g), SIGN_MESSAGE(g),
                          s->n); // t5 = z + r * d_A
            sb_fe_mont_mult(C_Y2(g), C_T5(g), C_T7(g),
                            s->n); // y2 = k^-1 * R * (z + r * d_A) * R^-1 mod N

            // mont_mul produces quasi-reduced output, so 0 is represented as N.
            // If signing has produced a signature with an S value of 0, this
            // indicates DRBG failure (again) and the signature is invalid.
            err |= SB_ERROR_IF(DRBG_FAILURE, sb_fe_equal(C_Y2(g), &s->n->p));

            state.stage = SB_SW_SIGN_OP_STAGE_DONE;
            *MULT_STATE(g) = state;
            *done = 1;
            return err;
        }
        default: {
            sb_sw_point_mult_continue(g, s);
            *done = 0;
            return SB_SUCCESS; // it's not done until the signing inversion is done
        }
    }
}

static void sb_sw_verify_start(sb_sw_context_t v[static const 1],
                               const sb_sw_curve_t s[static const 1])
{
    *MULT_STATE(v) = (sb_sw_context_saved_state_t) {
        .operation = SB_SW_INCREMENTAL_OPERATION_VERIFY_SIGNATURE,
        .stage = SB_SW_VERIFY_OP_STAGE_INV_S,
        .res = 1,
        .curve_id = s->id
    };
}

static _Bool sb_sw_verify_continue(sb_sw_context_t v[static const 1],
                                   const sb_sw_curve_t s[static const 1])
{
    sb_sw_context_saved_state_t state = *MULT_STATE(v);

    switch (state.stage) {
        case SB_SW_VERIFY_OP_STAGE_INV_S: {
            // A signature with either r or s as 0 or N is invalid;
            // see `sb_test_invalid_sig` for a unit test of this
            // check.
            state.res &= sb_sw_scalar_validate(VERIFY_QR(v), s);
            state.res &= sb_sw_scalar_validate(VERIFY_QS(v), s);
            sb_fe_mod_reduce(VERIFY_MESSAGE(v), s->n);

            // A message of zero is also invalid.
            state.res &= !sb_fe_equal(VERIFY_MESSAGE(v), &s->n->p);

            sb_fe_mont_convert(C_T5(v), VERIFY_QS(v), s->n); // t5 = s * R
            sb_fe_mod_inv_r(C_T5(v), C_T6(v), C_T7(v), s->n); // t5 = s^-1 * R

            *C_T6(v) = *VERIFY_MESSAGE(v);

            sb_fe_mont_mult(MULT_ADD_KG(v), C_T6(v), C_T5(v),
                            s->n); // k_G = m * s^-1
            sb_fe_mont_mult(MULT_K(v), VERIFY_QR(v), C_T5(v),
                            s->n); // k_P = r * s^-1

            state.stage = SB_SW_VERIFY_OP_STAGE_INV_Z;
            *MULT_STATE(v) = state;
            return 0;
        }
        case SB_SW_VERIFY_OP_STAGE_INV_Z:
        case SB_SW_VERIFY_OP_STAGE_LADDER: {
            sb_sw_point_mult_add_z_continue(v, s);
            return 0;
        }
        case SB_SW_VERIFY_OP_STAGE_TEST: {
            // This happens when p is some multiple of g that occurs within
            // the ladder, such that additions inadvertently produce a point
            // doubling. When that occurs, the private scalar that generated p is
            // also obvious, so this is bad news. Don't do this.
            state.res &= !(sb_fe_equal(C_X1(v), &s->p->p) &
                           sb_fe_equal(C_Y1(v), &s->p->p));

            sb_word_t ver = 0;

            // qr ==? x mod N, but we don't have x, just x * z^2
            // Given that qr is reduced mod N, if it is >= P - N, then it can be used
            // directly. If it is < P - N, then we need to try to see if the original
            // value was qr or qr + N.

            // Try directly first:
            sb_fe_mont_square(C_T6(v), MULT_Z(v), s->p); // t6 = Z^2 * R
            sb_fe_mont_mult(C_T7(v), VERIFY_QR(v), C_T6(v),
                            s->p); // t7 = r * Z^2
            ver |= sb_fe_equal(C_T7(v), C_X1(v));

            // If that didn't work, and qr < P - N, then we need to compare
            // (qr + N) * z^2 against x * z^2

            // If qr = P - N, then we do not compare against (qr + N),
            // because qr + N would be equal to P, and the X component of the
            // point is thus zero and should have been rejected.

            // See the small_r_signature tests, which generate signatures
            // where this path is tested.

            sb_fe_mod_add(C_T5(v), VERIFY_QR(v), &s->n->p,
                          s->p); // t5 = (N + r)
            sb_fe_mont_mult(C_T7(v), C_T5(v), C_T6(v),
                            s->p); // t7 = (N + r) * Z^2
            sb_fe_sub(C_T5(v), &s->p->p, &s->n->p); // t5 = P - N
            ver |= (sb_fe_lt(VERIFY_QR(v), C_T5(v)) & // r < P - N
                    sb_fe_equal(C_T7(v), C_X1(v))); // t7 == x

            state.res &= ver;
            state.stage = SB_SW_VERIFY_OP_DONE;
            *MULT_STATE(v) = state;
            return 1;
        }
        default: {
            return state.stage == SB_SW_VERIFY_OP_DONE;
        }
    }
}

static _Bool sb_sw_verify_is_finished(sb_sw_context_t v[static const 1])
{
    return MULT_STATE(v)->stage == SB_SW_VERIFY_OP_DONE;
}

// Generate a Z from SB_SW_FIPS186_4_CANDIDATES worth of DRBG-produced data
// in c->param_gen.buf. Note that this tests a fixed number of candidates, and
// if it succeeds, there is no bias in the generated Z values.
static sb_error_t sb_sw_z_from_buf(sb_sw_context_t ctx[static const 1],
                                   const sb_sw_curve_t s[static const 1],
                                   const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    sb_fe_from_bytes(MULT_Z(ctx), ctx->param_gen.buf, e);

    for (sb_size_t i = 1; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
        /* Is the current candidate valid? */
        const sb_word_t zv = sb_sw_z_validate(MULT_Z(ctx), s);

        /* Generate another candidate. */
        sb_fe_from_bytes(MULT_Z2(ctx),
                         &ctx->param_gen.buf[i * SB_ELEM_BYTES], e);

        /* If the current candidate is invalid, swap in the new candidate. */
        sb_fe_ctswap((sb_word_t) (zv ^ SB_UWORD_C(1)), MULT_Z(ctx),
                     MULT_Z2(ctx));
    }

    /* If this loop has not created a valid candidate, it means that the DRBG
     * has produced outputs with extremely low probability. */
    err |= SB_ERROR_IF(DRBG_FAILURE, !sb_sw_z_validate(MULT_Z(ctx), s));

    return err;
}

// Initial Z generation for Z blinding (Coron's third countermeasure)
static sb_error_t sb_sw_generate_z(sb_sw_context_t c[static const 1],
                                   sb_hmac_drbg_state_t* const drbg,
                                   const sb_sw_curve_t s[static const 1],
                                   const sb_data_endian_t e,
                                   const sb_byte_t* const d1, const size_t l1,
                                   const sb_byte_t* const d2, const size_t l2,
                                   const sb_byte_t* const d3, const size_t l3,
                                   const sb_byte_t* const label,
                                   const size_t label_len)
{
    sb_error_t err = SB_SUCCESS;

    if (drbg) {
        // Use the supplied data as additional input to the DRBG
        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            d1, d2, d3, label
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            l1, l2, l3, label_len
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg,
                                                    c->param_gen.buf,
                                                    SB_SW_FIPS186_4_CANDIDATES *
                                                    SB_ELEM_BYTES,
                                                    add, add_len);
    } else {
        // Initialize the HKDF with the input supplied
        sb_hkdf_extract_init(&c->param_gen.hkdf, NULL, 0);

        sb_hkdf_extract_update(&c->param_gen.hkdf, d1, l1);
        sb_hkdf_extract_update(&c->param_gen.hkdf, d2, l2);
        sb_hkdf_extract_update(&c->param_gen.hkdf, d3, l3);

        sb_hkdf_extract_finish(&c->param_gen.hkdf);

        sb_hkdf_expand(&c->param_gen.hkdf, label, label_len,
                       c->param_gen.buf,
                       SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);
    }

    // It is a bug if this ever fails; the DRBG reseed count should have
    // been checked already, and the DRBG limits should allow these inputs.
    SB_ASSERT(!err, "Z generation should never fail.");

    // Place the generated Z in MULT_Z(c) and validate it.
    err |= sb_sw_z_from_buf(c, s, e);

    return err;
}

// Generate a private key from pseudo-random data filled in buf. The
// fips186_4 parameter controls whether 1 is added to candidate values; this
// should be true unless this function is being used for RFC6979 per-message
// secret generation.
static sb_error_t sb_sw_k_from_buf(sb_sw_context_t ctx[static const 1],
                                   const _Bool fips186_4,
                                   const sb_sw_curve_t* const s,
                                   sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Generate the initial candidate.
    sb_fe_from_bytes(MULT_K(ctx), ctx->param_gen.buf, e);

    if (fips186_4) {
        // per FIPS 186-4 B.4.2: d = c + 1
        // if this overflows, the value was invalid to begin with, and the
        // resulting value is all zeros, which is also invalid.
        sb_fe_add(MULT_K(ctx), MULT_K(ctx), &SB_FE_ONE);
    }

    for (sb_size_t i = 1; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
        /* Is the current candidate valid? */
        sb_word_t kv = sb_sw_scalar_validate(MULT_K(ctx), s);

        /* Test another candidate. */
        sb_fe_from_bytes(MULT_Z(ctx),
                         &ctx->param_gen.buf[i * SB_ELEM_BYTES], e);

        if (fips186_4) {
            /* d = c + 1 */
            sb_fe_add(MULT_Z(ctx), MULT_Z(ctx), &SB_FE_ONE);
        }

        /* If the current candidate is invalid, swap in the new candidate. */
        sb_fe_ctswap((sb_word_t) (kv ^ SB_UWORD_C(1)), MULT_K(ctx),
                     MULT_Z(ctx));
    }

    /* If this loop has not created a valid candidate, it means that the DRBG
     * has produced outputs with extremely low probability. */
    err |= SB_ERROR_IF(DRBG_FAILURE, !sb_sw_scalar_validate(MULT_K(ctx), s));

    return err;
}

//// PUBLIC API:

/// FIPS 186-4-style private key generation. Note that this tests a fixed
/// number of candidates.
sb_error_t sb_sw_generate_private_key(sb_sw_context_t ctx[static const 1],
                                      sb_sw_private_t private[static const 1],
                                      sb_hmac_drbg_state_t drbg[static const 1],
                                      sb_sw_curve_id_t const curve,
                                      sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(private);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Avoid modifying the input drbg state if a generate call will fail.
    // It takes SB_SW_FIPS186_4_CANDIDATES generate calls to generate a private
    // key. Note that separate calls to the generate function are used per
    // FIPS 186-4 B.4.2, which specifies an iterative process involving
    // multiple calls to the generate function. When compiled for testing
    // (SB_TEST), it is possible to force the DRBG to generate an all-1s bit
    // pattern for a certain number of generate calls, which also allows
    // verification that the correct number of candidates are tested.
    err |= sb_hmac_drbg_reseed_required(drbg, SB_SW_FIPS186_4_CANDIDATES);

    SB_RETURN_ERRORS(err, ctx);

    for (sb_size_t i = 0; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
        err |= sb_hmac_drbg_generate_additional_dummy
            (drbg, &ctx->param_gen.buf[i * SB_ELEM_BYTES], SB_ELEM_BYTES);
        SB_ASSERT(!err, "Private key generation should never fail.");
    }

    SB_RETURN_ERRORS(err, ctx);

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    sb_fe_to_bytes(private->bytes, MULT_K(ctx), e);

    SB_RETURN(err, ctx);
}

// Private key generation from HKDF expansion.
sb_error_t sb_sw_hkdf_expand_private_key(sb_sw_context_t ctx[static const 1],
                                         sb_sw_private_t private[static const 1],
                                         sb_hkdf_state_t hkdf[static const 1],
                                         const sb_byte_t* const restrict info,
                                         size_t const info_len,
                                         sb_sw_curve_id_t const curve,
                                         sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of info
    sb_poison_input(info, info_len);

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(private);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the curve is invalid.
    SB_RETURN_ERRORS(err, ctx);

    /* Generate SB_SW_FIPS186_4_CANDIDATES values to test by expanding the
     * given HKDF instance with the given info. */
    sb_hkdf_expand(hkdf, info, info_len, ctx->param_gen.buf,
                   SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    sb_fe_to_bytes(private->bytes, MULT_K(ctx), e);

    SB_RETURN(err, ctx);
}

// Helper function for sb_sw_invert_private_key and
// sb_sw_composite_sign_wrap_message_digest.
// Performs a modular inversion of a field element stored in C_X1 using a
// generated blinding factor stored in MULT_K in the montgomery domain and
// stores the result in C_T6. Assumes that curve and field element have both
// already been validated.
static void sb_sw_invert_field_element
                 (sb_sw_context_t ctx[static const 1],
                  const sb_sw_curve_t* s)
{
    /* Perform the scalar inversion. */

    // X1 = blinding factor * R
    sb_fe_mont_convert(C_X1(ctx), MULT_K(ctx), s->n);

    // Y1 = scalar * R
    sb_fe_mont_convert(C_Y1(ctx), MULT_Z(ctx), s->n);

    // T5 = blinding factor * scalar * R
    sb_fe_mont_mult(C_T5(ctx), C_X1(ctx), C_Y1(ctx), s->n);

    // T5 = (blinding factor * scalar)^-1 * R
    sb_fe_mod_inv_r(C_T5(ctx), C_T6(ctx), C_T7(ctx), s->n);

    // T6 = (blinding factor * scalar)^-1 * blinding factor * R
    //    = scalar^-1 * R
    sb_fe_mont_mult(C_T6(ctx), C_T5(ctx), C_X1(ctx), s->n);
}

sb_error_t sb_sw_invert_private_key(sb_sw_context_t ctx[static const 1],
                                    sb_sw_private_t output[static const 1],
                                    const sb_sw_private_t private[static const 1],
                                    sb_hmac_drbg_state_t* drbg,
                                    sb_sw_curve_id_t const curve,
                                    sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private
    sb_poison_input(private, sizeof(sb_sw_private_t));

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(output);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    /* Scalar inversion blinding factor generation is done in one generate
     * call to the DRBG. */
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    // Bail out early if the curve is invalid or the DRBG needs to be reseeded.
    SB_RETURN_ERRORS(err, ctx);

    /* Generate a random scalar to use as part of blinding. */
    if (drbg != NULL) {
        /* The private key is supplied as additional input to the DRBG in
         * order to mitigate DRBG failure. */

        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg,
                                                    ctx->param_gen.buf,
                                                    SB_SW_FIPS186_4_CANDIDATES *
                                                    SB_ELEM_BYTES,
                                                    add, add_len);
        SB_ASSERT(!err, "Scalar blinding factor generation should never fail.");
    } else {
        sb_hkdf_extract(&ctx->param_gen.hkdf, NULL, 0,
                        private->bytes, SB_ELEM_BYTES);

        const sb_byte_t label[] = "sb_sw_invert_private_key";
        sb_hkdf_expand(&ctx->param_gen.hkdf,
                       label, sizeof(label),
                       ctx->param_gen.buf,
                       SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);
    }

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    /* At this point a possibly-invalid candidate is in MULT_K(ctx). */
    /* Check the supplied private key now. */

    sb_fe_from_bytes(MULT_Z(ctx), private->bytes, e);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(MULT_Z(ctx), s));

    /* Bail out if the private key is invalid or if blinding factor
     * generation failed. */
    SB_RETURN_ERRORS(err, ctx);

    // T6 = scalar^-1 * R
    sb_sw_invert_field_element(ctx, s);

    // T5 = scalar^-1
    sb_fe_mont_reduce(C_T5(ctx), C_T6(ctx), s->n);

    sb_fe_to_bytes(output->bytes, C_T5(ctx), e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_compute_public_key_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private
    sb_poison_input(private, sizeof(sb_sw_private_t));

    // Nullify the context.
    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    // Return invalid-curve and DRBG errors immediately.
    SB_RETURN_ERRORS(err, ctx);

    // Generate a Z for projective coordinate randomization.
    static const sb_byte_t label[] = "sb_sw_compute_public_key";
    err |= sb_sw_generate_z(ctx, drbg, s, e, private->bytes, SB_ELEM_BYTES,
                            NULL, 0, NULL, 0, label, sizeof(label));

    // Validate the private key before performing any operations.

    sb_fe_from_bytes(MULT_K(ctx), private->bytes, e);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(MULT_K(ctx), s));

    // Return DRBG failure and invalid private key errors before performing
    // the point multiplication.
    SB_RETURN_ERRORS(err, ctx);

    *MULT_POINT(ctx) = s->g_r;

    *MULT_STATE(ctx) =
        (sb_sw_context_saved_state_t) {
            .operation = SB_SW_INCREMENTAL_OPERATION_COMPUTE_PUBLIC_KEY,
            .curve_id = s->id
        };

    sb_sw_point_mult_start(ctx, s);

    return err;
}

sb_error_t sb_sw_compute_public_key_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_COMPUTE_PUBLIC_KEY);

    SB_RETURN_ERRORS(err, ctx);

    const sb_sw_curve_t* curve = NULL;
    err |= sb_sw_curve_from_id(&curve, MULT_STATE(ctx)->curve_id);
    SB_RETURN_ERRORS(err, ctx);

    *done = sb_sw_point_mult_continue(ctx, curve);

    return err;
}

sb_error_t sb_sw_compute_public_key_finish
    (sb_sw_context_t ctx[static const 1],
     sb_sw_public_t public[static const 1],
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(public);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_COMPUTE_PUBLIC_KEY);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_point_mult_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);
    SB_RETURN_ERRORS(err, ctx);

    // The output is quasi-reduced, so the point at infinity is (p, p).
    // This should never occur with valid scalars.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (sb_fe_equal(C_X1(ctx), &s->p->p) &
                        sb_fe_equal(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
                    "valid scalar.");

    sb_fe_to_bytes(public->bytes, C_X1(ctx), e);
    sb_fe_to_bytes(public->bytes + SB_ELEM_BYTES, C_Y1(ctx), e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_compute_public_key(sb_sw_context_t ctx[static const 1],
                                    sb_sw_public_t public[static const 1],
                                    const sb_sw_private_t private[static const 1],
                                    sb_hmac_drbg_state_t* const drbg,
                                    const sb_sw_curve_id_t curve,
                                    const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private
    sb_poison_input(private, sizeof(sb_sw_private_t));

    err |= sb_sw_compute_public_key_start(ctx, private, drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_compute_public_key_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_compute_public_key_finish(ctx, public, e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_valid_private_key(sb_sw_context_t ctx[static const 1],
                                   const sb_sw_private_t private[static const 1],
                                   const sb_sw_curve_id_t curve,
                                   const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private
    sb_poison_input(private, sizeof(sb_sw_private_t));

    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_K(ctx), private->bytes, e);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(MULT_K(ctx), s));

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_valid_public_key(sb_sw_context_t ctx[static const 1],
                                  const sb_sw_public_t public[static const 1],
                                  const sb_sw_curve_id_t curve,
                                  const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of public
    sb_poison_input(public, sizeof(sb_sw_public_t));

    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes, e);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES, e);

    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !sb_sw_point_validate(ctx, s));

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_compress_public_key(sb_sw_context_t ctx[static const 1],
                                     sb_sw_compressed_t compressed[static const 1],
                                     _Bool sign[static const 1],
                                     const sb_sw_public_t public[static const 1],
                                     sb_sw_curve_id_t curve,
                                     sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of public
    sb_poison_input(public, sizeof(sb_sw_public_t));

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(compressed);
    SB_NULLIFY(sign);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes, e);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES, e);

    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !sb_sw_point_validate(ctx, s));

    SB_RETURN_ERRORS(err, ctx);

    // Copy the X value to the compressed output.
    memcpy(compressed->bytes, public->bytes, SB_ELEM_BYTES);

    // The "sign" bit is the low order bit of the Y value.
    const sb_word_t sign_w = sb_fe_test_bit(MULT_POINT_Y(ctx), 0);
    *sign = (_Bool) sign_w;

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_decompress_public_key
    (sb_sw_context_t ctx[static const 1],
     sb_sw_public_t public[static const 1],
     const sb_sw_compressed_t compressed[static const 1],
     _Bool sign,
     sb_sw_curve_id_t curve,
     sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of compressed and sign
    sb_poison_input(compressed, sizeof(sb_sw_compressed_t));
    sb_poison_input(&sign, sizeof(sign));

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(public);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_POINT_X(ctx), compressed->bytes, e);
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID,
                       !sb_sw_point_decompress(ctx, (sb_word_t) sign, s));
    SB_RETURN_ERRORS(err, ctx);

    // Fully reduce X to [0, p)
    sb_fe_mod_reduce_full(MULT_POINT_X(ctx), s->p);

    sb_fe_to_bytes(public->bytes, MULT_POINT_X(ctx), e);
    sb_fe_to_bytes(public->bytes + SB_ELEM_BYTES, MULT_POINT_Y(ctx), e);

    SB_RETURN(err, ctx);
}

static sb_error_t sb_sw_multiply_shared_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e,
     const sb_sw_incremental_operation_t op)
{
    sb_error_t err = SB_SUCCESS;

    // The context has already been nullified.

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    SB_RETURN_ERRORS(err, ctx);

    // Only the X coordinate of the public key is used as the nonce, since
    // the Y coordinate is not an independent input.
    static const sb_byte_t label[] = "sb_sw_multiply_shared";
    err |= sb_sw_generate_z(ctx, drbg, s, e, private->bytes, SB_ELEM_BYTES,
                            public->bytes, SB_ELEM_BYTES,
                            NULL, 0, label, sizeof(label));

    sb_fe_from_bytes(MULT_K(ctx), private->bytes, e);

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes, e);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES, e);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(MULT_K(ctx), s));
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !sb_sw_point_validate(ctx, s));

    // Return early if the supplied public key does not represent a point on
    // the given curve.
    SB_RETURN_ERRORS(err, ctx);

    // Pre-multiply the point's x and y by R

    *C_X1(ctx) = *MULT_POINT_X(ctx);
    *C_Y1(ctx) = *MULT_POINT_Y(ctx);

    sb_fe_mont_convert(MULT_POINT_X(ctx), C_X1(ctx), s->p);
    sb_fe_mont_convert(MULT_POINT_Y(ctx), C_Y1(ctx), s->p);

    *MULT_STATE(ctx) = (sb_sw_context_saved_state_t) {
        .operation = op,
        .curve_id = s->id
    };

    sb_sw_point_mult_start(ctx, s);

    return err;
}

sb_error_t sb_sw_shared_secret_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private or public
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));

    // Nullify the context.
    SB_NULLIFY(ctx);

    err |= sb_sw_multiply_shared_start(ctx, private, public, drbg, curve, e,
                                       SB_SW_INCREMENTAL_OPERATION_SHARED_SECRET);

    return err;
}

sb_error_t sb_sw_shared_secret_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* curve = NULL;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SHARED_SECRET);

    err |= sb_sw_curve_from_id(&curve, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    *done = sb_sw_point_mult_continue(ctx, curve);

    return err;
}

sb_error_t sb_sw_shared_secret_finish(sb_sw_context_t ctx[static const 1],
                                      sb_sw_shared_secret_t secret[static const 1],
                                      const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* s = NULL;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(secret);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SHARED_SECRET);

    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_point_mult_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    // This should never occur with a valid private scalar.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (sb_fe_equal(C_X1(ctx), &s->p->p) &
                        sb_fe_equal(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
                    "valid scalar.");
    SB_RETURN_ERRORS(err, ctx);

    // Fully reduce the output to [0, p)
    sb_fe_mod_reduce_full(C_X1(ctx), s->p);
    sb_fe_to_bytes(secret->bytes, C_X1(ctx), e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_shared_secret(sb_sw_context_t ctx[static const 1],
                               sb_sw_shared_secret_t secret[static const 1],
                               const sb_sw_private_t private[static const 1],
                               const sb_sw_public_t public[static const 1],
                               sb_hmac_drbg_state_t* const drbg,
                               const sb_sw_curve_id_t curve,
                               const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private or public
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));

    err |= sb_sw_shared_secret_start(ctx, private, public, drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_shared_secret_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_shared_secret_finish(ctx, secret, e);

    SB_RETURN(err, ctx);
}


sb_error_t sb_sw_point_multiply_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private or public
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));

    // Nullify the context.
    SB_NULLIFY(ctx);

    err |= sb_sw_multiply_shared_start(ctx, private, public, drbg, curve, e,
                                       SB_SW_INCREMENTAL_OPERATION_POINT_MULTIPLY);

    return err;
}

sb_error_t sb_sw_point_multiply_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* s = NULL;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_POINT_MULTIPLY);

    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    *done = sb_sw_point_mult_continue(ctx, s);

    return err;
}

sb_error_t sb_sw_point_multiply_finish(sb_sw_context_t ctx[static const 1],
                                       sb_sw_public_t output[static const 1],
                                       const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* s = NULL;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(output);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_POINT_MULTIPLY);

    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_point_mult_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    // This should never occur with a valid private scalar.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (sb_fe_equal(C_X1(ctx), &s->p->p) &
                        sb_fe_equal(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
                    "valid scalar.");

    SB_RETURN_ERRORS(err, ctx);

    // Fully reduce X to [0, p)
    sb_fe_mod_reduce_full(C_X1(ctx), s->p);

    sb_fe_to_bytes(output->bytes, C_X1(ctx), e);
    sb_fe_to_bytes(output->bytes + SB_ELEM_BYTES, C_Y1(ctx), e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_point_multiply(sb_sw_context_t ctx[static const 1],
                                sb_sw_public_t output[static const 1],
                                const sb_sw_private_t private[static const 1],
                                const sb_sw_public_t public[static const 1],
                                sb_hmac_drbg_state_t* const drbg,
                                const sb_sw_curve_id_t curve,
                                const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private or public
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));

    err |= sb_sw_point_multiply_start(ctx, private, public, drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_point_multiply_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_point_multiply_finish(ctx, output, e);

    SB_RETURN(err, ctx);
}

// Shared message-signing logic; used for normal signing and known-answer test
// cases where the per-message secret is supplied. Assumes that the
// per-message secret and random Z value have already been generated in the
// supplied context.
static sb_error_t sb_sw_sign_message_digest_shared_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     const sb_sw_curve_t s[static const 1],
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private or message
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(message, sizeof(sb_sw_message_digest_t));

    // Validate the private scalar and message.

    sb_fe_from_bytes(SIGN_PRIVATE(ctx), private->bytes, e);
    sb_fe_from_bytes(SIGN_MESSAGE(ctx), message->bytes, e);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(SIGN_PRIVATE(ctx), s));

    // Reduce the message modulo N
    sb_fe_mod_reduce(SIGN_MESSAGE(ctx), s->n);

    // Return errors before performing the signature operation.
    SB_RETURN_ERRORS(err, ctx);

    sb_sw_sign_start(ctx, s);

    return err;
}

#ifdef SB_TEST

// This is an EXTREMELY dangerous method and is not exposed in the public
// header. Do not under any circumstances call this function unless you are
// running NIST CAVP tests.

sb_error_t sb_sw_sign_message_digest_with_k_beware_of_the_leopard
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     const sb_sw_private_t k[static const 1],
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // TODO: If this method causes an error we can remove the timing check. 
    // Timing checks are included in this method for extra coverage.
    // Indicate that this method's runtime should not depend on
    // the value of private, message, or k
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(message, sizeof(sb_sw_message_digest_t));
    sb_poison_input(k, sizeof(sb_sw_private_t));

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(signature);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Return early if the supplied curve is invalid.
    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_K(ctx), k->bytes, SB_ELEM_BYTES);

    // Validate the supplied scalar.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(MULT_K(ctx), s));

    // Generate a Z value for blinding.
    static const sb_byte_t label[] =
        "sb_sw_sign_message_digest_with_k_beware_of_the_leopard";

    err |= sb_sw_generate_z(ctx, NULL, s, e, private->bytes, SB_ELEM_BYTES,
                            message->bytes, SB_ELEM_BYTES, NULL, 0, label,
                            sizeof(label));

    // Return if the supplied scalar is invalid or Z generation failed.
    SB_RETURN_ERRORS(err, ctx);

    sb_sw_sign_message_digest_shared_start(ctx, private, message, s, e);

    _Bool done;
    do {
        err |= sb_sw_sign_continue(ctx, s, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    sb_fe_to_bytes(signature->bytes, C_X2(ctx), e);
    sb_fe_to_bytes(signature->bytes + SB_ELEM_BYTES, C_Y2(ctx), e);

    SB_RETURN(err, ctx);

}

#endif

sb_error_t sb_sw_sign_message_digest_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private or message
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(message, sizeof(sb_sw_message_digest_t));

    // Nullify the context.
    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    // It takes SB_SW_FIPS186_4_CANDIDATES calls to generate a per-message
    // secret and one to generate an initial Z
    if (provided_drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(provided_drbg,
                                            SB_SW_FIPS186_4_CANDIDATES + 1);
    }

    SB_RETURN_ERRORS(err, ctx);

    // If a DRBG is provided, FIPS186-4 mode is used. Otherwise, RFC6979
    // deterministic signature generation is used.
    const _Bool fips186_4 = (provided_drbg != NULL);

    // A convenient alias for the actual DRBG being used.
    sb_hmac_drbg_state_t* const drbg =
        (provided_drbg ? provided_drbg : &ctx->param_gen.drbg);

    if (fips186_4) {
        // FIPS 186-4-style per-message secret generation:
        // The private key and message are used (in native endianness) as
        // additional input to the DRBG in order to prevent catastrophic
        // entropy failure.

        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes, message->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES, SB_ELEM_BYTES
        };

        err |= sb_hmac_drbg_generate_additional_vec(provided_drbg,
                                                    &ctx->param_gen.buf[0],
                                                    SB_ELEM_BYTES, add,
                                                    add_len);

        // Provide additional input on each subsequent call in order to
        // ensure backtracking resistance in the DRBG.
        for (sb_size_t i = 1; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
            err |= sb_hmac_drbg_generate_additional_dummy
                (drbg,
                 &ctx->param_gen.buf[i * SB_ELEM_BYTES],
                 SB_ELEM_BYTES);
            SB_ASSERT(!err, "The DRBG should never fail to generate a "
                            "per-message secret.");
        }
    } else {
        // RFC6979 deterministic signature generation requires the scalar and
        // reduced message to be input to the DRBG in big-endian form.
        sb_fe_from_bytes(MULT_K(ctx), private->bytes, e);
        sb_fe_from_bytes(MULT_Z(ctx), message->bytes, e);

        // Reduce the message modulo N. Unreduced scalars will be tested later.
        sb_fe_mod_reduce(MULT_Z(ctx), s->n);

        // Convert the private scalar and reduced message back into a
        // big-endian byte string
        sb_fe_to_bytes(&ctx->param_gen.buf[0], MULT_K(ctx),
                       SB_DATA_ENDIAN_BIG);
        sb_fe_to_bytes(&ctx->param_gen.buf[SB_ELEM_BYTES], MULT_Z(ctx),
                       SB_DATA_ENDIAN_BIG);

        err |=
            sb_hmac_drbg_init(&ctx->param_gen.drbg,
                              &ctx->param_gen.buf[0], SB_ELEM_BYTES,
                              &ctx->param_gen.buf[SB_ELEM_BYTES],
                              SB_ELEM_BYTES,
                              NULL,
                              0);
        SB_ASSERT(!err, "DRBG initialization should never fail.");

        // This call to sb_hmac_drbg_generate can't be replaced by a call to
        // sb_hmac_drbg_generate_additional_dummy as it would break
        // compatibility with RFC6979 (and its test vectors).
        for (sb_size_t i = 0; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
            err |= sb_hmac_drbg_generate(drbg,
                                         &ctx->param_gen.buf[i * SB_ELEM_BYTES],
                                         SB_ELEM_BYTES);
            SB_ASSERT(!err, "The DRBG should never fail to generate a "
                            "per-message secret.");
        }
    }

    err |= sb_sw_k_from_buf(ctx, fips186_4, s, e);

    // If the DRBG has failed (produced SB_SW_FIPS186_4_CANDIDATES bad
    // candidates in a row), bail out early.
    SB_RETURN_ERRORS(err, ctx);

    // And now generate an initial Z. This uses the DRBG directly instead of
    // calling sb_sw_generate_z because the private key and message digest
    // have already been supplied as input to the DRBG. Dummy additional
    // input is provided instead in order to ensure backtracking resistance
    // of the DRBG.
    err |= sb_hmac_drbg_generate_additional_dummy(drbg,
                                                  ctx->param_gen.buf,
                                                  4 * SB_ELEM_BYTES);
    SB_ASSERT(!err, "The DRBG should never fail to generate a Z value.");

    if (!fips186_4) {
        // Nullify the RFC6979 DRBG before returning the context.
        SB_NULLIFY(&ctx->param_gen.drbg);
    }

    err |= sb_sw_z_from_buf(ctx, s, e);

    // If the DRBG has failed again, bail out early.
    SB_RETURN_ERRORS(err, ctx);

    // Now that per-message secret and random Z values have been generated,
    // start the message signing.
    return sb_sw_sign_message_digest_shared_start(ctx, private, message, s, e);
}

// Implemented in sb_sha256.c for sha256 message verification.
extern void
sb_sha256_finish_to_buffer(sb_sha256_state_t sha[static restrict 1]);

sb_error_t sb_sw_sign_message_sha256_start
    (sb_sw_context_t ctx[static const 1],
     sb_sha256_state_t sha[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    // Indicate that this method's runtime should not depend on
    // the value of private
    sb_poison_input(private, sizeof(sb_sw_private_t));

    sb_sha256_finish_to_buffer(sha);

    // This egregious cast works because sb_sw_message_digest_t is just a struct
    // wrapper for a bunch of bytes.
    const sb_sw_message_digest_t* const digest =
        (const sb_sw_message_digest_t*) (sha->buffer);

    return sb_sw_sign_message_digest_start(ctx, private, digest,
                                           provided_drbg, curve, e);
}

sb_error_t sb_sw_sign_message_digest_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* curve = NULL;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SIGN_MESSAGE_DIGEST);

    err |= sb_sw_curve_from_id(&curve, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    err |= sb_sw_sign_continue(ctx, curve, done);
    SB_RETURN_ERRORS(err, ctx);

    return err;
}

sb_error_t sb_sw_sign_message_digest_finish
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(signature);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SIGN_MESSAGE_DIGEST);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_sign_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_to_bytes(signature->bytes, C_X2(ctx), e);
    sb_fe_to_bytes(signature->bytes + SB_ELEM_BYTES, C_Y2(ctx), e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_sign_message_digest
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of private or message
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(message, sizeof(sb_sw_message_digest_t));

    err |= sb_sw_sign_message_digest_start(ctx, private, message,
                                           provided_drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_sign_message_digest_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_sign_message_digest_finish(ctx, signature, e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_sign_message_sha256
    (sb_sw_context_t ctx[static const 1],
     sb_sw_message_digest_t digest[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_byte_t* const input,
     size_t const input_len,
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    // Indicate that this method's runtime should not depend on
    // the value of private or input
    sb_poison_input(private, sizeof(sb_sw_private_t));
    sb_poison_input(input, input_len);
    
    // Compute the message digest and provide it as output.
    sb_sha256_message(&ctx->param_gen.sha, digest->bytes, input, input_len);

    return sb_sw_sign_message_digest(ctx, signature, private, digest,
                                     provided_drbg, curve, e);
}

sb_error_t sb_sw_composite_sign_wrap_message_digest
    (sb_sw_context_t ctx[static const 1],
     sb_sw_message_digest_t wrapped[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     sb_sw_curve_id_t const curve,
     sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of message or private
    sb_poison_input(message, sizeof(sb_sw_message_digest_t));
    sb_poison_input(private, sizeof(sb_sw_private_t));

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(wrapped);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    /* Scalar inversion blinding factor generation is done in one generate
     * call to the DRBG. */
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    // Bail out early if the curve is invalid or the DRBG needs to be reseeded.
    SB_RETURN_ERRORS(err, ctx);

    /* Generate a random scalar to use as part of blinding. */
    if (drbg != NULL) {
        /* The private key is supplied as additional input to the DRBG in
         * order to mitigate DRBG failure. */

        // Supply the private scalar and the message as drbg's additional input.
        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes, message->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES, SB_SHA256_SIZE
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg,
                                                    ctx->param_gen.buf,
                                                    SB_SW_FIPS186_4_CANDIDATES *
                                                    SB_ELEM_BYTES,
                                                    add, add_len);
        SB_ASSERT(!err, "Scalar blinding factor generation should never fail.");
    } else {
        // Update the hkdf with the private scalar and the message.
        sb_hkdf_extract_init(&ctx->param_gen.hkdf, NULL, 0);
        sb_hkdf_extract_update(&ctx->param_gen.hkdf,
                               private->bytes, SB_ELEM_BYTES);
        sb_hkdf_extract_update(&ctx->param_gen.hkdf,
                               message->bytes, SB_SHA256_SIZE);
        sb_hkdf_extract_finish(&ctx->param_gen.hkdf);

        const sb_byte_t label[] = "sb_sw_composite_sign_wrap_message_digest";
        sb_hkdf_expand(&ctx->param_gen.hkdf,
                       label, sizeof(label),
                       ctx->param_gen.buf,
                       SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);
    }

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    /* At this point a possibly-invalid candidate is in MULT_K(ctx). */
    /* Check the supplied private key now. */

    sb_fe_from_bytes(MULT_Z(ctx), private->bytes, e);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(MULT_Z(ctx), s));

    /* Bail out if the private key is invalid or if blinding factor
     * generation failed. */
    SB_RETURN_ERRORS(err, ctx);

    // T6 = scalar^-1 * R
    sb_sw_invert_field_element(ctx, s);

    // T5 = message_digest
    sb_fe_from_bytes(C_T5(ctx), message->bytes, e);
    sb_fe_mod_reduce(C_T5(ctx), s->n);

    // T7 = (scalar^-1 * R) * message_digest * R^-1
    //    = scalar^-1 * message_digest
    sb_fe_mont_mult(C_T7(ctx), C_T6(ctx), C_T5(ctx), s->n);

    sb_fe_to_bytes(wrapped->bytes, C_T7(ctx), e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_composite_sign_unwrap_signature
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t unwrapped[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_sw_curve_id_t const curve,
     sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of signature or private
    sb_poison_input(signature, sizeof(sb_sw_signature_t));
    sb_poison_input(private, sizeof(sb_sw_private_t));

    // Nullify the context
    SB_NULLIFY(ctx);
    SB_NULLIFY(unwrapped);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Return errors if curve is invalid
    SB_RETURN_ERRORS(err, ctx);

    // Convert the private scalar to a field element and validate.
    sb_fe_from_bytes(MULT_Z(ctx), private->bytes, e);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_validate(MULT_Z(ctx), s));

    // Convert the signature to field elements and validate.
    sb_fe_from_bytes(VERIFY_QR(ctx), signature->bytes, e);
    sb_fe_from_bytes(VERIFY_QS(ctx), signature->bytes + SB_ELEM_BYTES, e);
    sb_fe_mod_reduce(C_T6(ctx), s->n);

    err |= SB_ERROR_IF(SIGNATURE_INVALID,
                       !sb_sw_scalar_validate(VERIFY_QR(ctx), s));
    err |= SB_ERROR_IF(SIGNATURE_INVALID,
                       !sb_sw_scalar_validate(VERIFY_QS(ctx), s));

    // Return with errors if private key or signature did not validate.
    SB_RETURN_ERRORS(err, ctx);

    // Y1 = private * R
    sb_fe_mont_convert(C_Y1(ctx), MULT_Z(ctx), s->n);

    // T5 = s * private
    sb_fe_mont_mult(C_T5(ctx), C_Y1(ctx), VERIFY_QS(ctx), s->n);

    // Output (r, s)
    sb_fe_to_bytes(unwrapped->bytes, VERIFY_QR(ctx), e);
    sb_fe_to_bytes(unwrapped->bytes + SB_ELEM_BYTES, C_T5(ctx), e);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_verify_signature_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_public_t public[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of signature, public, or message
    sb_poison_input(signature, sizeof(sb_sw_signature_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));
    sb_poison_input(message, sizeof(sb_sw_message_digest_t));

    // Nullify the context.
    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    SB_RETURN_ERRORS(err, ctx);

    // Only the X coordinate of the public key is used as input to initial Z
    // generation, as the Y coordinate is not an independent input.
    static const sb_byte_t label[] = "sb_sw_verify_signature";
    err |= sb_sw_generate_z(ctx, drbg, s, e, public->bytes, SB_ELEM_BYTES,
                            signature->bytes, 2 * SB_ELEM_BYTES,
                            message->bytes, SB_ELEM_BYTES, label,
                            sizeof(label));

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes, e);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES, e);
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !sb_sw_point_validate(ctx, s));

    sb_fe_from_bytes(VERIFY_QR(ctx), signature->bytes, e);
    sb_fe_from_bytes(VERIFY_QS(ctx), signature->bytes + SB_ELEM_BYTES, e);
    sb_fe_from_bytes(VERIFY_MESSAGE(ctx), message->bytes, e);

    // Return early if the public key does not represent a point on the curve.
    SB_RETURN_ERRORS(err, ctx);

    sb_sw_verify_start(ctx, s);

    return err;
}

sb_error_t sb_sw_verify_signature_sha256_start
    (sb_sw_context_t ctx[static const 1],
     sb_sha256_state_t sha[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    // Indicate that this method's runtime should not depend on
    // the value of signature or public
    sb_poison_input(signature, sizeof(sb_sw_signature_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));

    sb_sha256_finish_to_buffer(sha);

    // This egregious cast works because sb_sw_message_digest_t is just a struct
    // wrapper for a bunch of bytes.
    const sb_sw_message_digest_t* const digest =
        (const sb_sw_message_digest_t*) (sha->buffer);

    return sb_sw_verify_signature_start(ctx, signature, public, digest, drbg,
                                        curve, e);
}

sb_error_t sb_sw_verify_signature_continue(sb_sw_context_t ctx[static const 1],
                                           _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* curve = NULL;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_VERIFY_SIGNATURE);

    err |= sb_sw_curve_from_id(&curve, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    *done = sb_sw_verify_continue(ctx, curve);

    return err;
}

sb_error_t sb_sw_verify_signature_finish(sb_sw_context_t ctx[static const 1])
{
    sb_error_t err = SB_SUCCESS;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_VERIFY_SIGNATURE);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_verify_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(SIGNATURE_INVALID, !MULT_STATE(ctx)->res);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_verify_signature(sb_sw_context_t ctx[static const 1],
                                  const sb_sw_signature_t signature[static const 1],
                                  const sb_sw_public_t public[static const 1],
                                  const sb_sw_message_digest_t message[static const 1],
                                  sb_hmac_drbg_state_t* const drbg,
                                  const sb_sw_curve_id_t curve,
                                  const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Indicate that this method's runtime should not depend on
    // the value of signature, public, or message
    sb_poison_input(signature, sizeof(sb_sw_signature_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));
    sb_poison_input(message, sizeof(sb_sw_message_digest_t));

    err |= sb_sw_verify_signature_start(ctx, signature, public, message,
                                        drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_verify_signature_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_verify_signature_finish(ctx);

    SB_RETURN(err, ctx);
}

sb_error_t sb_sw_verify_signature_sha256
    (sb_sw_context_t ctx[static const 1],
     sb_sw_message_digest_t digest[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_public_t public[static const 1],
     const sb_byte_t* const input,
     size_t const input_len,
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    // Indicate that this method's runtime should not depend on
    // the value of signature, public, or input
    sb_poison_input(signature, sizeof(sb_sw_signature_t));
    sb_poison_input(public, sizeof(sb_sw_public_t));
    sb_poison_input(input, input_len);

    // Compute the message digest and provide it as output.
    sb_sha256_message(&ctx->param_gen.sha, digest->bytes, input, input_len);

    return sb_sw_verify_signature(ctx, signature, public, digest, drbg,
                                  curve, e);
}

#ifdef SB_TEST
#define SB_SW_LIB_TESTS_IMPL
#include "sb_sw_lib_tests.c.h"
#endif
