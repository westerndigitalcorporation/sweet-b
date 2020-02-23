/** @file sb_error.h
 *  @brief private error return macros
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

#ifndef SB_ERROR_H
#define SB_ERROR_H

#include "sb_types.h"

#include <string.h>

#define SB_NULLIFY(ptr) do { \
    memset((ptr), 0, sizeof(*(ptr))); \
} while (0)

#define SB_ERROR_IF(err, cond) ((-(sb_error_t) (cond)) & (sb_error_t) \
SB_ERROR_## err)

#define SB_RETURN_ERRORS_2(err, zero_ctx) do { \
    if (err) { \
        SB_NULLIFY(zero_ctx); \
        return err; \
    } \
} while (0)

#define SB_RETURN_ERRORS_1(err, unused) do { \
    if (err) { \
        return err; \
    } \
} while (0)

#define SB_RETURN_ERRORS_n(a, b, c, ...) c(a, b)

#define SB_RETURN_ERRORS(...) \
    SB_RETURN_ERRORS_n(__VA_ARGS__, SB_RETURN_ERRORS_2, SB_RETURN_ERRORS_1, \
                       NOT_ENOUGH_ARGUMENTS)

#define SB_RETURN(err, zero_ctx) do { \
    SB_NULLIFY(zero_ctx); \
    return err; \
} while (0)

#define SB_ERRORS_4(err1, err2, err3, err4) \
    (((sb_error_t) (err1)) | ((sb_error_t) (err2)) | ((sb_error_t) (err3)) | \
     ((sb_error_t) (err4)))

#define SB_ERRORS_3(err1, err2, err3, unused) \
    (((sb_error_t) (err1)) | ((sb_error_t) (err2)) | ((sb_error_t) (err3)))

#define SB_ERRORS_2(err1, err2, unused1, unused2) \
    (((sb_error_t) (err1)) | ((sb_error_t) (err2)))

#define SB_ERRORS_1(err1, unused1, unused2, unused3) \
    ((sb_error_t) (err1))

#define SB_ERRORS_n(a, b, c, d, e, ...) e(a, b, c, d)

#define SB_ERRORS(...) \
    SB_ERRORS_n(__VA_ARGS__, SB_ERRORS_4, SB_ERRORS_3, SB_ERRORS_2, \
        SB_ERRORS_1, NOT_ENOUGH_ARGUMENTS)

#endif
