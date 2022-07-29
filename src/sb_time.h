/** @file sb_time.h
 *  @brief operations to test for timing differences based on inputs
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


#ifndef SB_TIME_H
#define SB_TIME_H

#ifndef SB_TIME
#define SB_TIME 0
#endif

#if SB_TIME
#include <valgrind/memcheck.h>
#endif

/** 
 * Poisons a memory region of len bytes, starting at addr, indicating that
 * execution time must not depend on the content of this memory region.
 * This function is used to mark all fields that contain or are derived from 
 * secret data.
 */
#if SB_TIME
#define sb_poison_input(addr, len) VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
#else
#define sb_poison_input(addr, len) do { /* Nothing */ } while (0)
#endif
/**
 * Removes the poison indicatior from a memory region of len bytes, starting
 * at addr, to signify that execution time is allowed to depend on the content
 * of this memory region. This function is used either on invalid input to 
 * indicate that we no do not make any timing guarantees on invalid data, or 
 * to prevent propagation of a poisoned state object to all of its output.
 */
#if SB_TIME
#define sb_unpoison_output(addr, len) VALGRIND_MAKE_MEM_DEFINED(addr, len)
#else
#define sb_unpoison_output(addr, len) do { /* Nothing */ } while (0)
#endif

#endif
