/** @file sb_sw_curves.h
 *  @brief private definitions of the short Weierstrass curves supported by Sweet B
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

#ifndef SB_SW_CURVES_H
#define SB_SW_CURVES_H

#include "sb_fe.h"
#include "sb_hmac_drbg.h"
#include "sb_sw_lib.h"

#if defined(SB_TEST) && !(SB_SW_P256_SUPPORT && SB_SW_SECP256K1_SUPPORT)
#error "Both SB_SW_P256_SUPPORT and SB_SW_SECP256K1_SUPPORT must be enabled for tests!"
#endif

// An elliptic curve defined in the short Weierstrass form:
// y^2 = x^3 + a*x + b

// In our case, a is -3 or 0. The oddly named minus_a_r_over_three
// is -a * R * 3^-1. For P256, this is just R. For secp256k1,
// this is p.

typedef struct sb_sw_curve_t {
    const sb_prime_field_t* p; // The prime field which the curve is defined over
    const sb_prime_field_t* n; // The prime order of the group, used for scalar computations
    sb_fe_t minus_a; // -a (3 for P256, 0 for secp256k1)
    const sb_fe_t* minus_a_r_over_three; // R for P256, 0 for secp256k1
    sb_fe_t b; // b ("random" for P256, 7 for secp256k1)
    sb_fe_pair_t g_r; // The generator for the group, with X and Y
    // multiplied by R
    sb_fe_pair_t h_r; // H = (2^257 - 1)^-1 * G, with X and Y multiplied by R
    sb_fe_pair_t g_h_r; // G + H, with X and Y multiplied by R
    sb_fe_pair_t dz_r; // 2 * (0, √𝐵) where √𝐵 has sign bit 0, if such a point exists
    sb_sw_curve_id_t id; // the curve ID for this curve
} sb_sw_curve_t;

#if SB_SW_P256_SUPPORT

// P256 is defined over F(p) where p is the Solinas prime
// 2^256 - 2^224 + 2^192 + 2^96 - 1
static const sb_prime_field_t SB_CURVE_P256_P = {
    .p = SB_FE_CONST_QR(0xFFFFFFFF00000001, 0x0000000000000000,
                        0x00000000FFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                        &SB_CURVE_P256_P),
    // p - 2 has Hamming weight 128. Factors:

    // Hamming weight 100
    .p_minus_two_f1 =
        SB_FE_CONST_QR(0x00000000F04D3168, 0xCA47D4443B0552EC,
                       0x999CB770B4B62944, 0x6571423119245693,
                       &SB_CURVE_P256_P),

    // Hamming weight 16
    .p_minus_two_f2 = SB_FE_CONST_QR(0, 0, 0, 0x110B9592F,
                                     &SB_CURVE_P256_P),

    .p_mp = (sb_word_t) UINT64_C(1),
    .r2_mod_p = SB_FE_CONST_QR(0x00000004FFFFFFFD, 0xFFFFFFFFFFFFFFFE,
                               0xFFFFFFFBFFFFFFFF, 0x0000000000000003,
                               &SB_CURVE_P256_P),
    .r_mod_p = SB_FE_CONST_QR(0x00000000FFFFFFFE, 0xFFFFFFFFFFFFFFFF,
                              0xFFFFFFFF00000000, 0x0000000000000001,
                              &SB_CURVE_P256_P),
    .bits = 256
};

// The prime order of the P256 group
static const sb_prime_field_t SB_CURVE_P256_N = {
    .p = SB_FE_CONST_QR(0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF,
                        0xBCE6FAADA7179E84, 0xF3B9CAC2FC632551,
                        &SB_CURVE_P256_N),

    // p - 2 has Hamming weight 169. Factors:

    // Hamming weight 85:
    .p_minus_two_f1 =
        SB_FE_CONST(0, 0x1E85574166915052,
                    0x945E2FDE9505C722, 0x24DC681531C30637),

    // Hamming weight 29:
    .p_minus_two_f2 = SB_FE_CONST(0, 0, 0x8, 0x6340A6B209A6CDA9),

    .p_mp = (sb_word_t) UINT64_C(0xCCD1C8AAEE00BC4F),
    .r2_mod_p =
        SB_FE_CONST_QR(0x66E12D94F3D95620, 0x2845B2392B6BEC59,
                       0x4699799C49BD6FA6, 0x83244C95BE79EEA2,
                       &SB_CURVE_P256_N),
    .r_mod_p =
        SB_FE_CONST_QR(0x00000000FFFFFFFF, 0x0000000000000000,
                       0x4319055258E8617B, 0x0C46353D039CDAAF,
                       &SB_CURVE_P256_N),
    .bits = 256
};

static const sb_sw_curve_t SB_CURVE_P256 = {
    .p = &SB_CURVE_P256_P,
    .n = &SB_CURVE_P256_N,
    .minus_a = SB_FE_CONST_QR(0, 0, 0, 3, &SB_CURVE_P256_P),
    .minus_a_r_over_three = &SB_CURVE_P256_P.r_mod_p,
    .b = SB_FE_CONST_QR(0x5AC635D8AA3A93E7, 0xB3EBBD55769886BC,
                        0x651D06B0CC53B0F6, 0x3BCE3C3E27D2604B,
                        &SB_CURVE_P256_P),
    .g_r = {
        SB_FE_CONST_QR(0x18905F76A53755C6, 0x79FB732B77622510,
                       0x75BA95FC5FEDB601, 0x79E730D418A9143C,
                       &SB_CURVE_P256_P),
        SB_FE_CONST_QR(0x8571FF1825885D85, 0xD2E88688DD21F325,
                       0x8B4AB8E4BA19E45C, 0xDDF25357CE95560A, &SB_CURVE_P256_P)
    },
    .h_r = {
        SB_FE_CONST_QR(0x3DABB6DD63469FDA, 0xD6636C75F0AEE963,
                       0x5E3BDEACE03C7C1E, 0x599DE4BA95AEDB71,
                       &SB_CURVE_P256_P),
        SB_FE_CONST_QR(0xCA44FCA952D8F196, 0x7AC346280EA74210,
                       0x77AE0F653969D951, 0x3EF12A374A0D7441, &SB_CURVE_P256_P)
    },
    .g_h_r = {
        SB_FE_CONST_QR(0x41FBBA1A1842253C, 0x2DDFA21F8A5F4377,
                       0x928D36DAB2C0BD2F, 0x2C487DEB40FA32F9,
                       &SB_CURVE_P256_P),
        SB_FE_CONST_QR(0xD041EE1CCC6223C9, 0xCD81EFC57B6F0943,
                       0xC614355C4D10A425, 0x3A1739581FCABBB7, &SB_CURVE_P256_P)
    },
    .dz_r = {
        SB_FE_CONST_QR(0x2D0F1BE2B5577CF9, 0x8DECDF26C01CE141,
                       0x07E28A0D562D7881, 0x8218884B2F38E1D6, &SB_CURVE_P256_P),
        SB_FE_CONST_QR(0x707320391E7826FA, 0x36925B3CB704A1FC,
                       0xE77DA7D78929B20A, 0x747C0826CD4F4E7B, &SB_CURVE_P256_P)
    },
    .id = SB_SW_CURVE_P256
};

#endif

#if SB_SW_SECP256K1_SUPPORT

// secp256k1 is defined over F(p):
static const sb_prime_field_t SB_CURVE_SECP256K1_P = {
    .p = SB_FE_CONST_QR(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFC2F,
                        &SB_CURVE_SECP256K1_P),

    // p - 2 has Hamming weight 249. Factors:

    // Hamming weight 64:
    .p_minus_two_f1 =
        SB_FE_CONST(0, 0, 0x037F6FF774E142D5, 0xC004A68677B5D811),

    // Hamming weight 58:
    .p_minus_two_f2 = SB_FE_CONST(0, 0x49,
                                  0x30562E37A2A6A014, 0x99B40D0074369E5D),

    .p_mp = (sb_word_t) UINT64_C(0xD838091DD2253531),
    .r2_mod_p =
        SB_FE_CONST_QR(0x0000000000000000, 0x0000000000000000,
                       0x0000000000000001, 0x000007A2000E90A1,
                       &SB_CURVE_SECP256K1_P),
    .r_mod_p =
        SB_FE_CONST_QR(0, 0, 0, 0x1000003D1,
                       &SB_CURVE_SECP256K1_P),

    .bits = 256
};

// The prime order of the secp256k1 group:
static const sb_prime_field_t SB_CURVE_SECP256K1_N = {
    .p = SB_FE_CONST_QR(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE,
                        0xBAAEDCE6AF48A03B, 0xBFD25E8CD0364141,
                        &SB_CURVE_SECP256K1_N),

    // p -2 has Hamming weight 196. Factors:

    // Hamming weight 134:
    .p_minus_two_f1 = SB_FE_CONST(0x3333333333333333, 0x3333333333333332,
                                  0xF222F8FAEFDB533F, 0x265D461C29A47373),

    // Hamming weight 2:
    .p_minus_two_f2 = SB_FE_CONST(0, 0, 0, 5),

    .p_mp = (sb_word_t) UINT64_C(0x4B0DFF665588B13F),
    .r2_mod_p = SB_FE_CONST_QR(0x9D671CD581C69BC5, 0xE697F5E45BCD07C6,
                               0x741496C20E7CF878, 0x896CF21467D7D140,
                               &SB_CURVE_SECP256K1_N),
    .r_mod_p = SB_FE_CONST_QR(0x0000000000000000, 0x0000000000000001,
                              0x4551231950B75FC4, 0x402DA1732FC9BEBF,
                              &SB_CURVE_SECP256K1_N),
    .bits = 256
};

static const sb_sw_curve_t SB_CURVE_SECP256K1 = {
    .p = &SB_CURVE_SECP256K1_P,
    .n = &SB_CURVE_SECP256K1_N,
    .minus_a = SB_FE_CONST_QR(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                              0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFC2F,
                              &SB_CURVE_SECP256K1_P),
    .minus_a_r_over_three = &SB_CURVE_SECP256K1_P.p,
    .b = SB_FE_CONST_QR(0, 0, 0, 7, &SB_CURVE_SECP256K1_P),
    .g_r = {
        SB_FE_CONST_QR(0x9981E643E9089F48, 0x979F48C033FD129C,
                       0x231E295329BC66DB, 0xD7362E5A487E2097,
                       &SB_CURVE_SECP256K1_P),
        SB_FE_CONST_QR(0xCF3F851FD4A582D6, 0x70B6B59AAC19C136,
                       0x8DFC5D5D1F1DC64D, 0xB15EA6D2D3DBABE2,
                       &SB_CURVE_SECP256K1_P)
    },
    .h_r = {
        SB_FE_CONST_QR(0x30A198DEBBCEFCAE, 0x537053ECF418BA53,
                       0xD8C36C4D8EC6CE34, 0xA381C3D21219CA1C,
                       &SB_CURVE_SECP256K1_P),
        SB_FE_CONST_QR(0xC198D9AFBD3AB7C6, 0xA5495A07C2AFCCE5,
                       0xF671D727A3637755, 0x446A2AD0C25FF948,
                       &SB_CURVE_SECP256K1_P)
    },
    .g_h_r = {
        SB_FE_CONST_QR(0x7BCE0EF2C201767E, 0xEC431492C7C96E54,
                       0x15EF56335DF148DB, 0xCDA8D7EF632EA0D8,
                       &SB_CURVE_SECP256K1_P),
        SB_FE_CONST_QR(0x3FB97A191E4DE5EA, 0xBBA21827B7EFEC04,
                       0xC7B977CC32E0BAA9, 0xC374BB2A1315A22F,
                       &SB_CURVE_SECP256K1_P)
    },
    // There is no point with an X coordinate of 0 on this
    // curve, but quasi-reduced values for dz_r still must be
    // supplied.
    .dz_r = {
        SB_FE_CONST_QR(0, 0, 0, 1,
                       &SB_CURVE_SECP256K1_P),
        SB_FE_CONST_QR(0, 0, 0, 1,
                       &SB_CURVE_SECP256K1_P)
    },
    .id = SB_SW_CURVE_SECP256K1
};

#endif

#endif
