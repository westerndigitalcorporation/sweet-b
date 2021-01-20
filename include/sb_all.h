/** @file sb_all.h
 *  @brief Top level header file for all Sweet B functionality.
 */

/** @page License
 *
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
 *
 */

/** @mainpage Sweet B
 *
 * This is Sweet B, a safe, compact, embeddable elliptic curve cryptography
 * library.
 *
 * https://github.com/westerndigitalcorporation/sweet-b
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates. Sweet B
 * is provided under the terms of the included \ref License.
 * 
 * Each Sweet B module defines a context structure and a set of functions that
 * operate on the structure. Documentation for these functions appears with
 * the structure that they operate on:
 *
 * - sb_sha256_state_t - SHA256 operations
 * - sb_hmac_sha256_state_t - HMAC-SHA256 operations
 * - sb_hkdf_state_t - HKDF and KBKDF operations
 * - sb_hmac_drbg_state_t - HMAC-DRBG operations
 * - sb_sw_context_t - Short Weierstrass curve operations
 *
 */

#ifndef SB_ALL_H
#define SB_ALL_H

#include <sb_sha256.h>
#include <sb_hmac_sha256.h>
#include <sb_hkdf.h>
#include <sb_hmac_drbg.h>
#include <sb_sw_lib.h>

#endif
