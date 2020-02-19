/** @file sb_fe_armv7.s
 *  @brief constant time prime-field element operations, ARMv7 w/DSP source
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

/* When reading this source, refer to sb_fe.c for corresponding C definitions
 * and to understand the algorithms being implemented */

/* All of the routines here are fully unrolled. .rept / .endr surrounds a
 * block of unrolled code, and .set is used to maintain a static iterator
 * across unrolled blocks.
 */

.syntax unified
.text
.align 4
.thumb

/* Constant time equality comparison

sb_word_t sb_fe_equal(const sb_fe_t left[static const 1],
                      const sb_fe_t right[static const 1])

r0 = left, r1 = right
return value in r0
*/

.globl sb_fe_equal
.type  sb_fe_equal, %function
.thumb_func

sb_fe_equal:
    push {r4, r5, r6, r7, lr}

    /* accumulates bit differences between left and right in r3 */
    /* r3 is caller save and on the first iteration is junk */

.set sb_i, 0
.rept 4 /* for (i = 0; i < 32; i += 8) */

    ldrd r4, r5, [r0, #sb_i] /* load two words of left into r4 and r5 */
    ldrd r6, r7, [r1, #sb_i] /* load two words of right into r6 and r7 */
.ifeq sb_i /* if i == 0 */
    eor r3, r4, r6 /* r3 = r4 ^ r6 */
.else
    eor r4, r4, r6 /* r4 ^= r6 */
.endif
    eor r5, r5, r7 /* r5 ^= r7 */
.ifgt sb_i /* if i > 0 */
    orr r3, r3, r4 /* r3 |= r4 */
.endif
    orr r3, r3, r5 /* r3 |= r5 */

    .set sb_i, sb_i + 8
.endr

    /* r | -r has bit 31 set if r is nonzero; v ^ 1 is logical negation */

    rsb r4, r3, #0 /* r4 = -r3 */
    orr r3, r3, r4 /* r3 |= r4 */
    lsr r3, r3, #31 /* r3 >>= 31; r3 is nonzero if there were any differences */
    eor r0, r3, #1 /* r0 = r3 ^ 1 */

    pop {r4, r5, r6, r7, pc}

.size   sb_fe_equal, .-sb_fe_equal

/* Returns 1 if the bit is set, 0 otherwise
 * While testing of bits set at secret indices in field elements should not
 * occur, this operation is still written in timing-independent fashion.

sb_word_t
sb_fe_test_bit(const sb_fe_t a[static const 1], const sb_bitcount_t bit)

r0 = a, r1 = bit
return value in r0
*/

.globl sb_fe_test_bit
.type  sb_fe_test_bit, %function
.thumb_func

/* The following uses ARM-specific features to perform the same logical
 * operation as the C source:
 * bic a, b, c, lsr #31 => a = b & (~(c >> 31))
 * This constructs the mask and applies it in one instruction.
 */

sb_fe_test_bit:
    push {r4, r5, r6, lr}
    and r2, r1, #31 /* r2 = r1 & 31, r2 is the bit within the word */

.set sb_i, 0
.set sb_l, 0
.set sb_h, 31

.rept 8 /* for (i = 0, l = 0, h = 31; i < 32; i += 4, l += 32, h += 32) */

    ldr r4, [r0, #sb_i] /* r4 = r0[i] */
    lsr r4, r4, r2 /* r4 >>= r2 */
    sub r5, r1, #sb_l /* r5 = r1 - l */
    rsb r6, r1, #sb_h /* r6 = h - r1 */
    bic r4, r4, r5, lsr #31 /* r4 &= (~(r5 >> 31)) */

.ifeq sb_i /* if i == 0 */
    bic r3, r4, r6, lsr #31 /* r3 = r4 & (~(r6 >> 31)) */
.else
    bic r4, r4, r6, lsr #31 /* r4 &= (~(r6 >> 31)) */
    orr r3, r3, r4 /* r3 |= r4 */
.endif

    .set sb_i, sb_i + 4
    .set sb_l, sb_l + 32
    .set sb_h, sb_h + 32
.endr

    /* the result is accumulated into the low bit of r3 */

    and r0, r3, #1 /* mask off any other bits */
    pop {r4, r5, r6, pc}

.size sb_fe_test_bit, .-sb_fe_test_bit

/* Field element addition with overflow

sb_word_t sb_fe_add(sb_fe_t dest[static const 1],
                    const sb_fe_t left[static const 1],
                    const sb_fe_t right[static const 1])

r0 = dest, r1 = left, r2 = right
return value in r0
*/

.globl sb_fe_add
.type sb_fe_add, %function
.thumb_func

sb_fe_add:
    push {r4, r5, r6, r7, lr}

/* Stores are interleaved with additions because on the Cortex-M4, there is a
 * single-word write buffer that allows a store to complete in one cycle if
 * it is followed by a non-memory operation */

.set sb_i, 0
.rept 4 /* for (i = 0; i < 32; i += 8) */
    ldrd r4, r5, [r1, #sb_i] /* r4 = r1[i]; r5 = r1[i + 4] */
    ldrd r6, r7, [r2, #sb_i] /* r6 = r2[i]; r7 = r1[i + 4] */
.ifeq sb_i /* if i == 0 */
    adds r4, r4, r6 /* r4 += r6, set carry */
.else
    adcs r4, r4, r6 /* r4 += r6 + carry, set carry */
.endif
    str r4, [r0, #sb_i] /* r0[i] = r4 */
    adcs r5, r5, r7 /* r5 += r7 + carry */
    .set sb_i, sb_i + 4
    str r5, [r0, #sb_i] /* r0[i + 4] = r5 */
    .set sb_i, sb_i + 4
.endr

    mov r0, #0 /* r0 = 0 */
    adc r0, r0, #0 /* r0 = 0 + carry */
    pop {r4, r5, r6, r7, pc}
.size sb_fe_add, .-sb_fe_add

/* Field element subtraction with incoming borrow

sb_word_t sb_fe_sub_borrow(sb_fe_t dest[static const 1],
                           const sb_fe_t left[static const 1],
                           const sb_fe_t right[static const 1],
                           sb_word_t borrow)

r0 = dest, r1 = left, r2 = right, r3 = borrow
return value in r0
*/

.globl sb_fe_sub_borrow
.type sb_fe_sub_borrow, %function
.thumb_func

sb_fe_sub_borrow:
    push {r4, r5, r6, r7, lr}

    /* On ARM, the carry flag is the logical negation of the borrow flag; in
     * other words, if no borrow is needed, the carry flag is set. */

    /* move the incoming borrow into the borrow (not-carry) flag */
    rsbs r3, #0 /* r3 = -r3, set borrow */

.set sb_i, 0
.rept 4 /* for (i = 0; i < 32; i += 8) */

    ldrd r4, r5, [r1, #sb_i] /* r4 = r1[i]; r5 = r1[i + 4] */
    ldrd r6, r7, [r2, #sb_i] /* r6 = r1[i]; r7 = r1[i + 4] */
    sbcs r4, r4, r6 /* r4 -= (r6 + borrow) */
    str r4, [r0, #sb_i] /* r0[i] = r4 */
.set sb_i, sb_i + 4
    sbcs r5, r5, r7 /* r5 -= (r7 + borrow) */
    str r5, [r0, #sb_i] /* r0[i + 4] = r5 */
.set sb_i, sb_i + 4
.endr

    /* sbc b, b, b => b = b - (b + !carry)
     * simplifies to b = -!carry
     * if there was a borrow on the final subtraction: carry = 0, b = -1
     * if there was no borrow: carry = 1, b = 0

     * rsb b, 0 => b = 0 - b
     * if there was a borrow on the final subtraction, b = 1
     * if there was no borrow, b = 0
     */

    /* move the borrow flag into r0 */
    sbc r0, r0, r0 /* r0 = r0 - (r0 + borrow) */
    rsb r0, #0 /* r0 = -r0 */

    pop {r4, r5, r6, r7, pc}
.size sb_fe_sub_borrow, .-sb_fe_sub_borrow

.globl sb_fe_lt
.type sb_fe_lt, %function
.thumb_func

/* Field element less-than, or subtract and return borrow

sb_word_t sb_fe_lt(const sb_fe_t left[static 1],
                   const sb_fe_t right[static 1])

r0 = left, r1 = right
return value in r0; does NOT modify the value of r1
*/

sb_fe_lt:
    push {r4, r5, r6, r7, lr}

.set sb_i, 0
.rept 4 /* for (i = 0; i < 32; i += 8) */

    ldrd r4, r5, [r0, #sb_i] /* r4 = r0[i]; r5 = r0[i + 4] */
    ldrd r6, r7, [r1, #sb_i] /* r6 = r1[i]; r7 = r1[i + 4] */
.ifeq sb_i /* if i == 0 */
    subs r4, r4, r6 /* r4 -= r6; set borrow */
.else
    sbcs r4, r4, r6 /* r4 -= (r6 + borrow); set borrow */
.endif
    sbcs r5, r5, r7 /* r5 -= (r7 + borrow); set borrow */
.set sb_i, sb_i + 8
.endr

    /* see sb_fe_sub_borrow for notes on how the borrow is returned */
    sbc r0, r0, r0 /* r0 = r0 - (r0 + borrow) */
    rsb r0, #0 /* r0 = -r0 */

    pop {r4, r5, r6, r7, pc}
.size sb_fe_lt, .-sb_fe_lt

/*
 * This helper routine subtracts p if c is 1; the subtraction is done
 * unconditionally, and the result is only written if c is 1
 * void sb_fe_cond_sub_p(sb_fe_t dest[static const restrict 1],
 *                       sb_word_t c,
 *                       const sb_fe_t p[static const restrict 1])
 *
 * r0 is dest, r1 is c, r2 is p
 */

.globl sb_fe_cond_sub_p
.type sb_fe_cond_sub_p, %function
.thumb_func

sb_fe_cond_sub_p:
    push {r4, r5, r6, r7, lr}

    /* On ARM processors with the DSP extension, the SEL instruction is used
     * for constant-time selection. Otherwise, an exclusive-or / and /
     * exclusive-or sequence is used. SEL selects based on the GE bits in the
     * CPSR, which are set when certain instructions overflow. Since the
     * condition has been converted into a mask, adding the condition to
     * itself will always overflow.
     *
     * See sb_fe_add for notes on store interleaving in the following.
     */

    rsb r1, r1, #0 /* r1 = -r1 */
    uadd8 r4, r1, r1 /* set selection mask from r1 */

.set sb_i, 0
.rept 4 /* for (i = 0; i < 32; i += 8) */

    ldrd r4, r5, [r0, #sb_i] /* r4 = r0[i]; r5 = r0[i + 4] */
    ldrd r6, r7, [r2, #sb_i] /* r6 = r2[i]; r7 = r0[i + 4] */
.ifeq sb_i /* if i == 0 */
    subs r6, r4, r6 /* r6 = r4 - r6, set borrow */
.else
    sbcs r6, r4, r6 /* r6 = r4 - (r6 + borrow), set borrow */
.endif
    sbcs r7, r5, r7 /* r7 = r5 - (r7 + borrow), set borrow */
    sel r4, r6, r4 /* r4 = c ? r6 : r4 */
    str r4, [r0, #sb_i] /* r0[i] = r4 */
    sel r5, r7, r5 /* r5 = c ? r7 : r5 */
.set sb_i, sb_i + 4
    str r5, [r0, #sb_i] /* r0[i + 4] = r5 */
.set sb_i, sb_i + 4
.endr

    pop {r4, r5, r6, r7, pc}
.size sb_fe_cond_sub_p, .-sb_fe_cond_sub_p

/*
 * This helper adds 1 or (p + 1), depending on c.
 *
 * void sb_fe_cond_add_p_1(sb_fe_t dest[static const restrict 1],
 *                         sb_word_t c,
 *                         const sb_fe_t p[static const restrict 1])
 *
 * r0 is dest, r1 is c, r2 is p
 */

.globl sb_fe_cond_add_p_1
.type sb_fe_cond_add_p_1, %function
.thumb_func

sb_fe_cond_add_p_1:
    push {r4, r5, r6, r7, lr}

    /* set selection from r1; see sb_fe_cond_sub_p */
    rsb r1, r1, #0 /* r1 = -r1 */
    uadd8 r4, r1, r1 /* set selection from r1 */

    /* first pass: add 1 to first half of dest */
    ldm r0, {r4, r5, r6, r7} /* load r4-r7 with 4 words from r0 */
    adds r4, r4, #1 /* r4++; set carry */
    adcs r5, r5, #0 /* r5 += carry; set carry */
    adcs r6, r6, #0 /* r6 += carry; set carry */
    adcs r7, r7, #0 /* r7 += carry; set carry */
    stmia r0!, {r4, r5, r6, r7} /* store r4-r7 at r0; r0 += 16 */

    /* second pass: add 1 to the second half of dest */
    ldm r0, {r4, r5, r6, r7} /* load r4-r7 with 4 words from r0 */
    adcs r4, r4, #0 /* r4 += carry; set carry */
    adcs r5, r5, #0 /* r5 += carry; set carry */
    adcs r6, r6, #0 /* r6 += carry; set carry */
    adcs r7, r7, #0 /* r7 += carry; set carry */
    stmia r0!, {r4, r5, r6, r7} /* store r4-r7 at r0; r0 += 16 */

    sub r0, r0, #32 /* r0 -= 32; */

.set sb_i, 0
.rept 4 /* for (i = 0; i < 32; i += 8) */
    ldrd r4, r5, [r0, #sb_i] /* r4 = r0[i]; r5 = r0[i + 4] */
    ldrd r6, r7, [r2, #sb_i] /* r6 = r0[i]; r7 = r0[i + 4] */
.ifeq sb_i /* if i == 0 */
    adds r6, r4, r6 /* r6 += r4; set carry */
.else
    adcs r6, r4, r6 /* r6 += r4 + carry; set carry */
.endif
    adcs r7, r5, r7 /* r7 += r5 + carry; set carry */
    sel r4, r6, r4 /* r4 = c ? r6 : r4 */
    str r4, [r0, #sb_i] /* r0[i] = r4 */
    sel r5, r7, r5 /* r5 = c ? r7 : r5 */
.set sb_i, sb_i + 4
    str r5, [r0, #sb_i] /* r0[i + 4] = r5 */
.set sb_i, sb_i + 4
.endr

    pop {r4, r5, r6, r7, pc}
.size sb_fe_cond_add_p_1, .-sb_fe_cond_add_p_1

/*
 * Constant-time swap of field elements.
 *
 * void sb_fe_ctswap(sb_word_t c,
 *                   sb_fe_t a[static const restrict 1],
 *                   sb_fe_t b[static const restrict 1])
 *
 * r0 is c, r1 is a, r2 is b
 */

.globl sb_fe_ctswap
.type sb_fe_ctswap, %function
.thumb_func

sb_fe_ctswap:
    push {r4, r5, r6, r7, lr}

    /* set selection from r0; see sb_fe_cond_sub_p */
    rsb r0, r0, #0 /* r0 = -r0 */
    uadd8 r4, r0, r0 /* set selection from r0 */

.set sb_i, 0

.rept 4 /* for (i = 0; i < 32; i += 8) */
    ldrd r4, r5, [r1, #sb_i] /* r4 = r1[i]; r5 = r1[i + 4] */
    ldrd r6, r7, [r2, #sb_i] /* r6 = r2[i]; r7 = r2[i + 4] */
    sel r3, r6, r4 /* r3 = c ? r6 : r4 */
    str r3, [r1, #sb_i] /* r1[i] = r3 */
    sel r3, r4, r6 /* r3 = c ? r4 : r6 */
    str r3, [r2, #sb_i] /* r2[i] = r3 */
    .set sb_i, sb_i + 4
    sel r3, r7, r5 /* r3 = c ? r7 : r5 */
    str r3, [r1, #sb_i] /* r1[i + 4] = r3 */
    sel r3, r5, r7 /* r3 = c ? r5 : r7 */
    str r3, [r2, #sb_i] /* r2[i + 4] = r3 */
    .set sb_i, sb_i + 4
.endr

    pop {r4, r5, r6, r7, pc}
.size sb_fe_ctswap, .-sb_fe_ctswap

/*
 * Montgomery multiplication
 *
 * void sb_fe_mont_mult(sb_fe_t A[static const restrict 1],
 *                      const sb_fe_t x[static const 1],
 *                      const sb_fe_t y[static const 1],
 *                      const sb_prime_field_t p[static const 1])
 *
 * r0 is A, r1 is x, r2 is y, r3 is p
 * p[32] is p->mp
 */

.global sb_fe_mont_mult
.type sb_fe_mont_mult, %function
.thumb_func

sb_fe_mont_mult:
    push {r4, r5, r6, r7, r8, r9, r10, r11, lr}

    ldr ip, [r3, #32] /* use ip as p->mp */

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
     * 1. carry := 0
     * 2. For i from 0 to (n - 1) do:
     * 2.1: c := 0; c2 := 0
     * 2.2: For j from 0 to (n - 1) by 2 do:
     * 2.2.2: If i == 0 then:
     * 2.2.2.1: (c, t) := x_i * y_j + c; (c, t2) := x_i * y_(j + 1) + c
     * 2.2.2.2: else: (c, t) := a_0 + x_i * y_j + c;
     *                (c, t2) := a_1 + x_i * y_(j + 1) + c
     * 2.2.3: If j == 0 then: u_i = t * m' mod b
     * 2.2.4: (c2, t) := t + u_i * m_j + c2
     * 2.2.5: If j > 0 then: A[j - 1] = t
     * 2.2.6: (c2, t2) := t2 + u_i * m_(j + 1) + c2
     * 2.2.7: A[j] = t2
     * 2.3: A[n - 1] = (c + c2 + carry); set carry
     * 3: If A > m or carry == 1 then A := A - m
     * 4: Return A
     *
     * Notably:
     * 1. There is no explicit A := 0 step; rather, on the first iteration
     *    zero values are loaded into registers instead of loading from A.
     * 2. u_i is computed when A + x_i * y_0 is computed as part of computing
     *    A + x_i * y + u_i * m.
     * 3. The division by b is handled by an implicit word shift in storing
     *    results back to A; the lowest word is not stored, and subsequent
     *    words are stored at an offset. The highest bit in A is kept in the
     *    carry flag.
     * 4. The implementation is fully unrolled, so all comparisons to i and j
     *    take place at macro-assembly time, not at runtime.
     *
     */

.set sb_i, 0
.rept 8 /* for (i = 0; i < 32; i += 4) */
.set sb_j, 0
    mov r10, #0 /* use r10 as c */
    mov r11, #0 /* use r11 as c2 */
    ldr r8, [r1, #sb_i] /* use r8 as x_i */
.rept 4 /* for (j = 0; j < 32; j += 8) */
    ldrd r6, r7, [r2, #sb_j] /* r6 = r2[j]; r7 = r2[j + 4] */
.ifeq sb_i /* if i == 0 */
    mov r4, #0 /* r4 = 0 */
    mov r5, #0 /* r5 = 0 */
.else
    ldrd r4, r5, [r0, #sb_j] /* r4 = r0[j]; r5 = r0[j + 4] */
.endif
    umaal r4, r10, r8, r6 /* (r10, r4) = r8 * r6 + r10 + r4 */
    umaal r5, r10, r8, r7 /* (r10, r5) = r8 * r7 + r10 + r5 */
.ifeq sb_j /* if j == 0 */
    mul r9, r4, ip /* use r9 as u_i: r9 = r4 * ip = (a_0 + x_i * y_0) * m' */
.endif
    ldrd r6, r7, [r3, #sb_j] /* r6 = r3[j]; r7 = r3[j + 4] */
    umaal r4, r11, r9, r6 /* (r11, r4) = r9 * r6 + r11 + r4 */
.ifgt sb_j /* if j > 0 */
.set sb_A, sb_j - 4
    str r4, [r0, #sb_A] /* r0[j - 4] = r4 */
.endif
    umaal r5, r11, r9, r7 /* (r11, r5) = r9 * r7 + r11 + r5 */
.set sb_j, sb_j + 4
.set sb_A, sb_j - 4
    str r5, [r0, #sb_A] /* r0[j] = r4 */
.set sb_j, sb_j + 4
.endr
.ifeq sb_i /* if i == 0 */
    adds r4, r10, r11 /* r4 = r10 + r11, set carry */
.else
    adcs r4, r10, r11 /* r4 = r10 + r11 + carry, set carry */
.endif
    str r4, [r0, #28] /* r0[28] = r4 */
.set sb_i, sb_i + 4
.endr

    /* move carry into ip */
    mov ip, #0 /* r1 = 0 */
    adc ip, ip, #0 /* r1 = r1 + 0 + carry */

    mov r1, r0 /* move A into r1 */
    mov r0, r3 /* move p into r0 for sb_fe_lt */

    bl sb_fe_lt /* r0 == p < A */

    orr ip, ip, r0 /* ip = (ip | r0) == (carry | (p < A)) */
    mov r0, r1 /* r0 = A */
    mov r1, ip /* r1 = (carry | (p < A)) */
    mov r2, r3 /* r2 = p */

    bl sb_fe_cond_sub_p

    pop {r4, r5, r6, r7, r8, r9, r10, r11, pc}
.size sb_fe_mont_mult, .-sb_fe_mont_mult
