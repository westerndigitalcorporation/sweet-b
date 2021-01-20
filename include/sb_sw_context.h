/** @file sb_sw_context.h
 *  @brief Context structure for short Weierstrass curves
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

#ifndef SB_SW_CONTEXT_H
#define SB_SW_CONTEXT_H

#include <sb_types.h>
#include <sb_hmac_drbg.h>
#include <sb_hkdf.h>
#include <stdalign.h>

/** @brief Size of the parameter buffer in SB_ELEM_BYTES number of elements.
 *  This value is set as large as it can be in order to keep the size of
 *  ::sb_sw_context_t to 512 bytes.
 */
#define SB_SW_CONTEXT_PARAM_BUF_ELEMS 4

/** @privatesection */

/** @def SB_CONTEXT_SIZE_ASSERT
  * @brief Statically assert that the size of the given structure is the given
  * number of bytes. */

#ifdef SB_TEST
#define SB_CONTEXT_SIZE_ASSERT(context, size) \
_Static_assert(1, "obvious")
#else
#define SB_CONTEXT_SIZE_ASSERT(context, size) \
_Static_assert(sizeof(context) == size, #context " should be " #size " bytes long.")
#endif

/** @struct sb_sw_context_params_t
 *  @brief Private context structure representing possibly-generated parameters.
 */
typedef struct sb_sw_context_params_t {
    sb_fe_t k, ///< Scalar parameter
            z; ///< Projective coordinate Z value, usually
} sb_sw_context_params_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_params_t, 64);

/** @struct sb_sw_context_param_gen_t
 *  @brief Private context structure for parameter generation.
 */
typedef struct sb_sw_context_param_gen_t {
    /// At most one DRBG or HKDF state instance. Once Z candidates have
    /// been generated in buf, the DRBG or HKDF instance is no longer
    /// used, and the space may be reused for validity testing of Z
    /// candidates.
    union {
        sb_hmac_drbg_state_t drbg; ///< DRBG state
        sb_hkdf_state_t hkdf; ///< HKDF state
        sb_sha256_state_t sha; ///< Used for complete-message signing
        sb_fe_t z2; ///< Candidate Z value during Z generation
    };

    /// Buffer used for HKDF or DRBG output during parameter generation.
    sb_byte_t buf[SB_SW_CONTEXT_PARAM_BUF_ELEMS * SB_ELEM_BYTES];
} sb_sw_context_param_gen_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_param_gen_t, 424);

/** @struct sb_sw_context_curve_arith_t
 *  @brief Private context structure for curve arithmetic operations.
 */
typedef struct sb_sw_context_curve_arith_t {
    sb_fe_pair_t p[2]; ///< Temporaries used to represent curve points
} sb_sw_context_curve_arith_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_curve_arith_t, 128);

/** @struct sb_sw_context_curve_arith_temporaries_t
 *  @brief Temporaries for curve arithmetic methods.
 */
typedef struct sb_sw_context_curve_arith_temporaries_t {
    sb_fe_t t[4]; ///< Temporaries used for raw field element values
} sb_sw_context_curve_arith_temporaries_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_curve_arith_temporaries_t, 128);

/** @struct sb_sw_context_sign_t
 *  @brief Private context structure for signing operations.
 */
typedef struct sb_sw_context_sign_t {
    sb_fe_t message; ///< Message to sign
    sb_fe_t priv; ///< Private scalar for signing
} sb_sw_context_sign_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_sign_t, 64);

/** @struct sb_sw_context_mult_t
 *  @brief Private context structure for point-scalar multiplication operations.
 */
typedef struct sb_sw_context_mult_t {
    sb_fe_pair_t point; ///< Input point
} sb_sw_context_mult_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_mult_t, 64);

/** @struct sb_sw_context_verify_common_t
 *  @brief Private context structure common to all verification phases.
 */
typedef struct sb_sw_context_verify_common_t {
    sb_fe_t qr; ///< R component of input signature
} sb_sw_context_verify_common_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_verify_common_t, 32);

/** @struct sb_sw_context_verify_early_t
 *  @brief Private context structure used early in signature verification.
 */
typedef struct sb_sw_context_verify_early_t {
    sb_fe_t message, ///< Message to verify, as reduced field element
            qs;      ///< S component of signature to verify
} sb_sw_context_verify_early_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_verify_early_t, 64);

/** @struct sb_sw_context_verify_late_t
 *  @brief Private context structure used late in signature verification.
 */
typedef struct sb_sw_context_verify_late_t {
    sb_fe_t kg; ///< The scalar to be used with the base point G
    sb_fe_pair_t pg; ///< The value of P + G in affine coordinates
} sb_sw_context_verify_late_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_verify_late_t, 96);

/** @struct sb_sw_context_verify_t
 *  @brief Private context structure used during signature verification.
 */
typedef struct sb_sw_context_verify_t {
    /// Common definitions to both verify phases
    sb_sw_context_verify_common_t common;

    /// Either early or late-phase members
    union {
        /// Early verification phase members
        sb_sw_context_verify_early_t early;
        /// Late verification phase members
        sb_sw_context_verify_late_t late;
    };
} sb_sw_context_verify_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_verify_t, 128);

/** @enum sb_sw_incremental_operation_value_t
  * @brief Incremental operation currently in progress */

typedef enum sb_sw_incremental_operation_value_t {
    /// No operation currently in progress
    SB_SW_INCREMENTAL_OPERATION_NONE = 0,

    /// See ::sb_sw_compute_public_key_start
    SB_SW_INCREMENTAL_OPERATION_COMPUTE_PUBLIC_KEY,
    
    /// See ::sb_sw_shared_secret_start
    SB_SW_INCREMENTAL_OPERATION_SHARED_SECRET,

    /// See ::sb_sw_point_multiply_start
    SB_SW_INCREMENTAL_OPERATION_POINT_MULTIPLY,

    /// See ::sb_sw_sign_message_digest_start
    SB_SW_INCREMENTAL_OPERATION_SIGN_MESSAGE_DIGEST,

    /// See ::sb_sw_verify_signature_start
    SB_SW_INCREMENTAL_OPERATION_VERIFY_SIGNATURE
} sb_sw_incremental_operation_value_t; /**< Convenience typedef */

/** Wrapper used for ABI compatibility */
typedef uint32_t sb_sw_incremental_operation_t;

/** @enum sb_sw_point_mult_op_stage_t
  * @brief Current stage of the point-scalar multiplication operation */

typedef enum sb_sw_point_mult_op_stage_t {
    /// Main ladder stage
    SB_SW_POINT_MULT_OP_STAGE_LADDER = 0,

    /// Z inversion for affine coordinate recovery
    SB_SW_POINT_MULT_OP_STAGE_INV_Z,

    /// Operation completed
    SB_SW_POINT_MULT_OP_DONE
} sb_sw_point_mult_op_stage_t; /**< Convenience typedef */

/** @enum sb_sw_sign_op_stage_t
  * @brief Current stage of the signing operation. Starts from
    sb_sw_point_mult_op_stage_t::SB_SW_POINT_MULT_OP_DONE */

typedef enum sb_sw_sign_op_stage_t {
    /// Per-message secret inversion
    SB_SW_SIGN_OP_STAGE_INV = SB_SW_POINT_MULT_OP_DONE,

    /// Operation completed
    SB_SW_SIGN_OP_STAGE_DONE
} sb_sw_sign_op_stage_t; /**< Convenience typedef */

/** @enum sb_sw_verify_op_stage_t
  * @brief Current stage of the signature verification operation. */

typedef enum sb_sw_verify_op_stage_t {
    /// S component inversion
    SB_SW_VERIFY_OP_STAGE_INV_S = 0,

    /// Z coordinate inversion for affine P + G computagion
    SB_SW_VERIFY_OP_STAGE_INV_Z,

    /// Ladder phase
    SB_SW_VERIFY_OP_STAGE_LADDER,

    /// Validation of computed ladder output
    SB_SW_VERIFY_OP_STAGE_TEST,

    /// Verification computed
    SB_SW_VERIFY_OP_DONE
} sb_sw_verify_op_stage_t; /**< Convenience typedef */

/** @typedef sb_sw_op_stage_t
 *  @brief Current operation stage.
 *  May be one of:
 *  - sb_sw_point_mult_op_stage_t
 *  - sb_sw_sign_op_stage_t
 *  - sb_sw_verify_op_stage_t
 */
typedef uint32_t sb_sw_op_stage_t;

/// Wrapper for sb_sw_curve_id_value_t values for ABI stability. This
/// duplicates a typedef in sb_sw_lib.h, which includes this file; the
/// definition is included in sb_sw_lib.h for documentation purposes.
typedef uint32_t sb_sw_curve_id_t;

/** @struct sb_sw_context_saved_state_t
  * @brief Saved state for an incremental operation.
  */

typedef struct sb_sw_context_saved_state_t {
    /// Incremental operation in progress. Used to report an error when
    /// attempting to continue an operation different than the one that was
    /// used to initialize the context.
    sb_sw_incremental_operation_t operation;
    sb_sw_curve_id_t curve_id; ///< Curve being operated on
    sb_sw_op_stage_t stage; ///< Current stage of the operation
    sb_size_t i; ///< Index of the ladder, if appropriate

    /// Saved parameters for specific operations
    union {
        /// Saved parameters used in point-scalar multiplication
        struct {
            sb_word_t inv_k, ///< K was (additively) inverted
                      k_one, ///< K is equal to one
                      swap;  ///< Swap meaning of ladder registers
        };

        /// Saved parameters used in signature verification
        struct {
            sb_word_t res; ///< Result accumulator
        };
    };
} sb_sw_context_saved_state_t; /**< Convenience typedef */

// sb_word_t varies in size depending on SB_WORD_SIZE. The maximum size of
// this structure is 16 + 3 * 8 = 40 bytes. However, when SB_WORD_SIZE is
// less than 4, the structure will be padded; thus, the size assertion is
// disabled in that case.
#if SB_WORD_SIZE >= 4
SB_CONTEXT_SIZE_ASSERT(sb_sw_context_saved_state_t, 16 + 3 * sizeof(sb_word_t));
#endif

/** @struct sb_sw_context_param_use_t
 *  @brief Private context structure used during all curve operations.
 */
typedef struct sb_sw_context_param_use_t {
    /// Stores the two point registers used in the Montgomery ladder and in
    /// the dual scalar-point multiplication-addition used for verification.
    sb_sw_context_curve_arith_t curve_arith;

    /// Stores the point to be multiplied against in ECDH (or the generator
    /// during message signing and public key verification), or the public key
    /// during signature verification.
    sb_sw_context_mult_t mult;

    /// Storage for curve temporaries during an operation, or state saved by
    /// incremental operations upon yielding to the caller
    union {
        /// State saved across incremental operations.
        sb_sw_context_saved_state_t saved_state;

        /// Basic temporaries used during all curve arithmetic.
        sb_sw_context_curve_arith_temporaries_t curve_temporaries;
    };

    /// Temporaries for either signing or verification operations
    union {
        /// Temporaries used during message signing.
        sb_sw_context_sign_t sign;

        /// Temporaries used during signature verification.
        sb_sw_context_verify_t verify;
    };
} sb_sw_context_param_use_t; /**< Convenience typedef */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_param_use_t, 448);

/** @publicsection */

/** @struct sb_sw_context_t
 *  @brief Context structure for short Weierstrass curves. You are
 *  responsible for allocating this and passing it to curve functions.
 */
typedef struct sb_sw_context_t {
    /** @privatesection */
    /// Possibly-generated parameters.
    sb_sw_context_params_t params;

    union {
        /// State used during parameter generation.
        sb_sw_context_param_gen_t param_gen;

        /// Parameter use during curve arithmetic.
        sb_sw_context_param_use_t param_use;
    };
} sb_sw_context_t; /**< Convenience typedef */

/** @privatesection */

SB_CONTEXT_SIZE_ASSERT(sb_sw_context_t, 512);

#ifndef SB_TEST
// sb_size_t is a uint32_t, whereas sb_word_t can be anything between uint8_t
// and uint64_t. The purpose of this is to ensure that in FFI bindings,
// sb_sw_context_t can be allocated as an appropriately aligned blob of bytes
// instead of exposing its representation, which is opaque in any case.
_Static_assert(alignof(sb_sw_context_t) ==
                   (alignof(sb_word_t) < alignof(sb_size_t) ?
                    alignof(sb_size_t) :
                    alignof(sb_word_t)),
               "sb_sw_context_t should be aligned to the minimum of sb_word_t "
               "or sb_size_t");
#endif

#endif
