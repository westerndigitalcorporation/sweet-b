/** @file sb_test_list.h
 *  @brief Private, multiply-included list of Sweet B tests
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

#ifdef SB_TEST_IMPL

// Known answer tests using examples from FIPS 180-2
// Can be found in their respective files.
SB_DEFINE_TEST(sha256_fips_180_2_1);
SB_DEFINE_TEST(sha256_fips_180_2_2);
SB_DEFINE_TEST(sha256_fips_180_2_3);
SB_DEFINE_TEST(hmac_sha256);
SB_DEFINE_TEST(hmac_drbg);
SB_DEFINE_TEST(hmac_drbg_errors);
SB_DEFINE_TEST(hkdf);

// These tests are for general field operations
// and can be found in sb_fe_tests.c.h
SB_DEFINE_TEST(fe);
SB_DEFINE_TEST(mod_double);
SB_DEFINE_TEST(mont_mult);
SB_DEFINE_TEST(mont_mult_overflow);
SB_DEFINE_TEST(mod_expt_p);
SB_DEFINE_TEST(mod_sqrt);

// Testing Keygen, ECDH, ECDSA and underlying mathematics for elliptic curves
// in the short weierstrass form. Can be found in sb_sw_lib_tests.c.h

// Simple tests to check for correctness of underlying elliptic curve
// operations such as secp256k1's endomorphism property, the Montgomery ladder,
// and Shamir's trick.
SB_DEFINE_TEST(ladder_simple);
SB_DEFINE_TEST(secp256k1_endomorphism);
SB_DEFINE_TEST(exceptions);
SB_DEFINE_TEST(sw_h);
SB_DEFINE_TEST(p256_dz);
SB_DEFINE_TEST(sw_point_mult_add);
// Known answer tests for keygen, shared_secret, and sign/verify work as they
// should.
SB_DEFINE_TEST(hkdf_expand_private_p256);
SB_DEFINE_TEST(hkdf_expand_private_secp256k1);
SB_DEFINE_TEST(compute_public);
SB_DEFINE_TEST(valid_private);
SB_DEFINE_TEST(valid_public);
SB_DEFINE_TEST(shared_secret);
SB_DEFINE_TEST(shared_secret_cavp_1);
SB_DEFINE_TEST(compressed_pub_shared_secret);
SB_DEFINE_TEST(compressed_pub_verify);
SB_DEFINE_TEST(p256_zero_x);
SB_DEFINE_TEST(shared_secret_secp256k1);
SB_DEFINE_TEST(sign_rfc6979);
SB_DEFINE_TEST(sign_rfc6979_sha256);
SB_DEFINE_TEST(sign_secp256k1);
SB_DEFINE_TEST(sign_catastrophe);
SB_DEFINE_TEST(verify);
SB_DEFINE_TEST(verify_james);
SB_DEFINE_TEST(verify_invalid);
// Use pk recovery to test the possibility of a small r signature not verifying
// correctly the first time.
SB_DEFINE_TEST(small_r_signature_p256);
SB_DEFINE_TEST(small_r_signature_secp256k1);
SB_DEFINE_TEST(small_r_boundary_p256);
SB_DEFINE_TEST(small_r_boundary_secp256k1);
SB_DEFINE_TEST(pk_recovery);
SB_DEFINE_TEST(pk_recovery_james);
// Tests to ensure that all values are checked for validity before moving on to
// computation.
SB_DEFINE_TEST(candidates);
SB_DEFINE_TEST(sw_early_errors);
SB_DEFINE_TEST(sw_invalid_scalar);
SB_DEFINE_TEST(sw_invalid_sig_p256);
SB_DEFINE_TEST(sw_invalid_sig_secp256k1);
// Randomized tests for expected functionality.
// Each takes a drbg and at each iteration generates a keypair to run tests.
SB_DEFINE_TEST(composite_key_wrap_p256);
SB_DEFINE_TEST(composite_key_wrap_secp256k1);
SB_DEFINE_TEST(sw_point_mult_add_rand);
SB_DEFINE_TEST(invert_iter);
SB_DEFINE_TEST(invert_iter_secp256k1);
SB_DEFINE_TEST(decompress_iter);
SB_DEFINE_TEST(decompress_iter_secp256k1);
SB_DEFINE_TEST(decompress_rand);
SB_DEFINE_TEST(decompress_rand_secp256k1);
SB_DEFINE_TEST(shared_iter);
SB_DEFINE_TEST(shared_iter_secp256k1);
SB_DEFINE_TEST(sign_iter);
SB_DEFINE_TEST(sign_iter_secp256k1);

SB_DEFINE_TEST(wycheproof_ecdh_secp256k1);
SB_DEFINE_TEST(wycheproof_ecdh_p256);
SB_DEFINE_TEST(wycheproof_ecdsa_secp256k1);
SB_DEFINE_TEST(wycheproof_ecdsa_p256);
SB_DEFINE_TEST(wycheproof_hmac_sha256);

#ifndef SB_TEST_TIS

// NIST CAVP tests
// Can be found in sb_test_cavp.c
SB_DEFINE_TEST(cavp_ecdh_shared_secret_p256);
SB_DEFINE_TEST(cavp_signatures_p256_sha1);
SB_DEFINE_TEST(cavp_signatures_p256_sha224);
SB_DEFINE_TEST(cavp_signatures_p256_sha256);
SB_DEFINE_TEST(cavp_signatures_p256_sha384);
SB_DEFINE_TEST(cavp_signatures_p256_sha512);
SB_DEFINE_TEST(cavp_hmac_sha256);
SB_DEFINE_TEST(cavp_sha256_small);
SB_DEFINE_TEST(cavp_sha256_long);
SB_DEFINE_TEST(cavp_sha256_monte);
SB_DEFINE_TEST(cavp_hmac_drbg_sha256);

#endif

#endif
