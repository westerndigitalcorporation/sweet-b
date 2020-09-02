<!--
 
 README.md: yes, the license applies to this file too
 
 SPDX-License-Identifier: BSD-3-Clause

 This file is part of Sweet B, a safe, compact, embeddable library for
 elliptic curve cryptography.

 https://github.com/westerndigitalcorporation/sweet-b

 Copyright (c) 2020 Western Digital Corporation or its affiliates.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
 may be used to endorse or promote products derived from this software without
 specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 
-->

![Sweet B Logo](sweet-b.svg)

Sweet B is a library which implements public key elliptic curve cryptography
(ECC) using the NIST P-256 and SECG secp256k1 curves. Sweet B is:

* *Safe:* known attack vectors have been accounted for, design decisions have
  been documented, and the API has been designed to eliminate the possibility of
  catastrophic misuse when possible.
* *Clear:* the library is thoroughly commented and unit tested, and is designed
  to be easy to read and review.
* *Compact:* the library is compact in code size, uses a minimal 512-byte
  working context, and does not assume that keys and other intermediary products
  can be allocated on the stack.
* *Audited:* a third-party review of the library was carried out prior to public
 release, and the full report and status of remediations are [available
  publicly](audit/README.md).

You should consider using Sweet B if you need to implement elliptic curve 
Diffie-Hellman shared-secret generation (ECDH) or elliptic curve digital 
signature generation and verification (ECDSA) in a memory-constrained 
environment. For instance, the P-256 curve is used in Bluetooth Low Energy 
Security, and is often implemented on memory-constrained devices for this 
purpose.

## Why is it called Sweet B?

Sweet B is a pun on both the Short Weierstrass form of elliptic curves and on
the NSA's [Suite B](https://en.wikipedia.org/wiki/NSA_Suite_B_Cryptography) set
of cryptographic algorithms.

## Where did Sweet B come from?

Sweet B was developed by [Western Digital](https://www.westerndigital.com/).

## How was Sweet B reviewed?

Western Digital engaged the security research firm
[Trail of Bits](https://www.trailofbits.com) to review Sweet B prior to its
 public release. The resulting report and the status of remediations for
  specific findings are [available publicly](audit/README.md).

## How does Sweet B protect against known attacks on ECC?

Sweet B provides mitigation for several classes of known faults and attacks:

* _Timing analyses_ reveal secret information by measuring the time that it
  takes to perform cryptographic operations. Sweet B prevents this by ensuring
  that all operations run in constant time with respect to the input data
  (though different curves have different performance characteristics).
* _Power analyses_ reveal secret information by measuring the amount of power
  consumed during cryptographic operations. Sweet B addresses this by using
  *randomized projective coordinates*, also called Z blinding. The special case
  of *zero value analysis* has been addressed by representing reduced integers
  modulo 𝑝 as integers within the range [1, 𝑝], ensuring that the points
  (0, ±√𝐵 ∙ 𝑍³, 𝑍) on applicable curves do not cause observable multiplications
  by low-Hamming-weight field elements.
* _Safe-error analyses_ reveal secret information by causing hardware faults
  during cryptographic operations and observing whether the fault affects the
  output. Sweet B mitigates these attacks through the use of a regular
  Montgomery ladder with no dummy computations prior to the final bit.
* _Per-message secret reuse_ causes the private key to be revealed to anyone
  receiving more than one signature with the same secret. Sweet B prevents this
  by providing an internal implementation of a deterministic random-bit
  generator (DRBG) using HMAC-SHA256 for per-message secret generation in ECDSA
  signing. When an externally seeded instance of the DRBG is provided, the
  private key and message are provided as additional input to the DRBG, ensuring
  that even in cases of entropy source failure, per-message secrets are never
  re-used. When no externally seeded instance is provided,
  [RFC6979](https://tools.ietf.org/html/rfc6979) deterministic signing is used.
  The internal HMAC-DRBG is also used for projective-coordinate randomization
  when no external entropy source is available.

It is impossible to guarantee that side-channel mitigations in a
portable C implementation will perform correctly with all compilers and with all
target platforms. Please analyze Sweet B and your use case carefully if using
 it on a platform where assembly support is not available.

## What makes Sweet B different than other implementations?

Sweet B is designed to be simple, safe, compact, and embeddable. In order to be
as portable as possible, any word size from 8 to 64 bits may be used; you should
choose the word size that corresponds to the size of your hardware multiplier.
Sweet B does not assume that it's possible to store large amounts of working
state on the stack; instead, a separately allocated 512-byte working context is
required, which may be placed on the stack, heap allocated, or statically
allocated per the user's needs.

Simple, compact implementations of SHA256, HMAC-SHA256, and HMAC-DRBG are
provided both for internal use and for use in producing digests of data to be
signed or verified. You are also encouraged to use the HMAC-DRBG implementation
for random number generation in your system, assuming you have access to a
sufficient source of hardware entropy.

Sweet B uses Montgomery multiplication, which eliminates the need for separate
reduction steps. This makes it easier to produce a constant-time library
supporting multiple primes, and also makes Sweet B fast compared with other
embeddable implementations in C. However, there are faster implementations of
ECC if you have more working memory or more code storage available.

Sweet B has been carefully designed to avoid side channel attacks, including
timing and power analyses. All field operations and elliptic curve operations
are designed to run in constant time, and projective coordinate randomization
consistently used. All functions take an optional DRBG parameter, and you are
strongly encouraged to supply a properly-seeded DRBG whenever possible to
mitigate power-based side channel attacks.

## How do I get started with Sweet B?

[`sb_sw_lib.h`](src/sb_sw_lib.h) is the main entry point for ECC operations on
short Weierstrass curves (P-256 and secp256k1). For hashing and random number
generation, see [`sb_sha256.h`](src/sb_sha256.h) and
[`sb_hmac_drbg.h`](src/sb_hmac_drbg.h). Each file contains a number of test 
cases; if you compile Sweet B with `-DSB_TEST`, you can run them using the 
main routine in [`sb_test.c`](src/sb_test.c).

You can set the word size used in Sweet B with the `SB_WORD_SIZE` preprocessor
macro. By default, this is set to 4, meaning that 32-bit multiplies producing
64-bit results will be used. On 8- or 16-bit microcontrollers, or on 32-bit
microcontrollers without full 64-bit multiply output (such as the Cortex-M0+),
you should set this to 1 or 2. On 64-bit x86 systems, you may want to set the
multiplication size to 8 to use 128-bit multiplication output.

You can disable either of the short Weierstrass curves Sweet B supports by
setting the preprocessor defines `SB_SW_P256_SUPPORT` or
`SB_SW_SECP256K1_SUPPORT` to 0. If you have a little more program memory 
available, you may want to set `SB_UNROLL` to a value between 1 and 3 
(inclusive); on Cortex-M4, `SB_UNROLL=2` provides the best balance between 
size and speed.

If you have ARM support for your processor (see [`sb_fe_armv7.s`](src/sb_fe_armv7.s)
for an example of this); define `SB_FE_ASM` to 1 when compiling the code, and
supply a separate ARM assembly implementation for the core field-element
arithmetic routines listed in [`sb_fe.h`](src/sb_fe.h) as being supported by
assembly. The supplied example implementation targets 32-bit ARM Thumb
processors with DSP extensions; examples of this include the Cortex-M4, M7, and
A5.

[CMake](https://cmake.org/) build support is provided; to use it, create a
directory for your build, run `cmake` with the path to the Sweet B sources, and
then run `make` to build. To run the unit tests with the clang undefined
behavior and address sanitizers, pass `-DCMAKE_C_COMPILER=clang` to `cmake` if
clang is not your default compiler.

## Annotated Bibliography

Neal Koblitz. A Course in Number Theory and Cryptography. Springer-Verlag, 1994.

> This is a rather old text, and the section on elliptic curves is dated.
> However, it remains an outstanding reference for any discussion of finite
> fields.

Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone. [Handbook of
Applied Cryptography](http://cacr.uwaterloo.ca/hac/). CRC Press, 1996.

> Another older text, but the chapter on efficient implementation remains a
> worthwhile reference for basic field arithmetic algorithms.

Jean-Sébastien Coron. [Resistance Against Differential Power Analysis For
Elliptic Curve
Cryptosystems](http://www.crypto-uni.lu/jscoron/publications/dpaecc.pdf). In
_Cryptographic Hardware and Embedded Systems (CHES) 1999_.

> Introduces several countermeasures against power analyses, the third of which
> is the randomized projective coordinate technique used in Sweet B (often
> described as "Coron's third countermeasure").

Tetsuya Izu, Bodo Möller, and Tsuyoshi Takagi. [Improved Elliptic Curve
Multiplication Methods Resistant against Side Channel
Attacks](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.436.831&rep=rep1&type=pdf).
In _Progress in Cryptology — INDOCRYPT 2002_.

> Discusses the SPA and DPA-resistance of the Montgomery ladder for elliptic curves.

Raveen R. Goundar, Marc Joye, Atsuko Miyaji, Matthieu Rivain, and Alexandre
Venelli. [Scalar multiplication on Weierstraß elliptic curves from Co-Z
arithmetic](http://www.matthieurivain.com/files/jcen11b.pdf). In _Journal of
Cryptographic Engineering, Vol. 1, 161 (2011)_.

> Introduces the co-Z Montgomery ladder on Weierstrass curves, and discusses its
> derivation.

 Matthieu Rivain. [Fast and Regular Algorithms for Scalar Multiplication over
 Elliptic Curves](https://eprint.iacr.org/2011/338.pdf). _IACR Cryptology ePrint
 Archive, Report 2011/338_.

 > The main reference for Sweet B. Describes the co-Z addition and initial
 > affine-to-Jacobian point doubling formulae implemented in the library.

Shay Gueron and Vlad Krasnov. [Fast prime field elliptic-curve cryptography with
256-bit primes](https://eprint.iacr.org/2013/816.pdf). In _Journal of
Cryptographic Engineering, Vol. 5, 141 (2011)_.

> Discusses the use of Montgomery multiplication with the P-256 field prime,
> specifically due to its "Montgomery friendly" property.
