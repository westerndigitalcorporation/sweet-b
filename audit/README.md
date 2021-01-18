<!--
 
 audit.md: yes, the license applies to this file too
 
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

![Sweet B Logo](../sweet-b.svg)

Cryptographic primitive implementation is notoriously difficult, as any error
in the implementation could allow an attacker to recover private information. To
reduce the possibility of such error and obtain an independent evaluation of
the robustness of our work, [Western Digital](https://www.westerndigital.com/)
engaged the security research firm [Trail of Bits](https://www.trailofbits.com/)
to review Sweet B prior to its public release. During the review, Trail of Bits
assessed the conformance, test coverage, API design, and timing behavior of the
library, and developed an harness based on [qemu](https://www.qemu.org) to
experimentally validate that instruction traces captured from library
routines are independent of secret inputs to the routines.

The [full report](WDC_Sweet_B_Final_Report.pdf) detailed six main findings, as
well as a set of informational and long term recommendations. The status of
these findings and recommendations are detailed below.

## Summary of remediation status

| *Finding*    | *Severity*    | *Summary* | *Status* |
|--------------|---------------|-----------|----------|
| [*TOB-SB-004*](#tob-sb-004-debug-definitions-may-violate-layout-invariants-relied-on-by-assembly) | Medium        | Debug definitions may violate layout invariants relied on by assembly | Remediated |
| [*TOB-SB-003*](#tob-sb-003-c-library-routines-may-violate-timing-guarantees) | Low           | C library routines may violate timing guarantees. | See below |
| [*TOB-SB-001*](#tob-sb-001-debug-asserts-violate-timing-guarantees) | Low           | Debug asserts violate timing guarantees | Remediated |
| [*TOB-SB-006*](#tob-sb-006-hmac_drbg-does-not-provide-backtracking-resistance-without-additional-input) | Low           | HMAC_DRBG does not provide backtracking resistance without additional input | Remediated |
| [*TOB-SB-002*](#tob-sb-002-sdl-mandates-use-of-annex-k-bounds-checking-interfaces) | Informational | SDL mandates use of Annex K bounds-checking interfaces | See below |
| [*TOB-SB-005*](#tob-sb-005-apis-for-ecdsa-signing-and-verification-do-not-enforce-secure-hashing) | Informational | APIs for ECDSA signing and verification do not enforce secure hashing | Remediated |
| [Non-security findings](#non-security-related-findings) | N/A     | Several typos and code quality suggestions | Remediated |
| [Long-term recommendations](#long-term-recommendations) | N/A | Several API, documentation, and build structure suggestions | Not yet incorporated |
| [Additional unit testing](#additional-unit-testing) | N/A | Improvement of unit test coverage | Partially incorporated |

## TOB-SB-004: Debug definitions may violate layout invariants relied on by assembly

This finding has been remediated in commit
[`2180aa8`](https://github.com/westerndigitalcorporation/sweet-b/commit/2180aa81c5aef5a128541b642d05134a42fd1033)
by ensuring that debug defines cannot be enabled if assembly support is
compiled in, and as per TOB-SB-001, that debug definitions cannot be used
outside the unit testing harness.

## TOB-SB-003: C library routines may violate timing guarantees

Cryptographic routines must be timing-invariant with respect to secret inputs
in order to avoid information leakage that may be leveraged by an adversary.
The C language provides no guarantees about timing, and C library routines
might violate timing constraints through unexpected data-dependence. Trail of
Bits has recommended avoiding the use of C library routines in timing-sensitive
operations. Unfortunately, the naïve approach of replacing calls to library
routine with hand-written code has a significant pitfall in that the
compiler is also permitted to replace any section of code with a call to an
equivalent C library routine. In particular, hand-written loops for memory
copying or initialization and structure assignments are both candidates for
replacement with calls to library routines.

The GNU C Compiler supports an option called `-ffreestanding` which purports to
prevent the compiler from assuming that standard C library routines exist,
but due to a [longstanding bug](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56888),
this option does not prevent the compiler from inserting calls to `memcpy` in
all circumstances.

In the short term, we believe the risk of data-dependent timing in C library
routines is low, as these routines have little reason to inspect the data
being operated on. In the long term, the intended mitigation is to provide
assembly routines for memory copying and initialization with defined timing
behavior.

## TOB-SB-001: Debug asserts violate timing guarantees

This finding has been remediated in commit [`e8ccfb3`](https://github.com/westerndigitalcorporation/sweet-b/commit/e8ccfb3e6f99ccf1b48897c7cbc85aab7d1ce17d)
by ensuring that debug asserts can only be enabled when compiling the unit
test harness. Attempting to enable debug asserts in other configurations
will result in a preprocessor error.

## TOB-SB-006: HMAC_DRBG does not provide backtracking resistance without additional input

This finding has been remediated in commit [`75c5f58`](https://github.com/westerndigitalcorporation/sweet-b/commit/75c5f5893021dc94d764857ebc35fe4c32cc6422)
by providing a new API `sb_hmac_drbg_generate_additional_dummy` which
provides static additional input to the HMAC_DRBG generate routine, and by
using this API in all contexts where additional input is not otherwise
available, with the exception of RFC6979 signing. The existing
`sb_hmac_drbg_generate` API has been retained for compliance with
[NIST SP 800-90A Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final),
but the new API is recommended for use instead.

## TOB-SB-002: SDL mandates use of Annex K bounds-checking interfaces

In order to facilitate integration with as many embedded and low-level host
environments as possible, Sweet B is written in C. Improper use of
memory-related routines in C is a longstanding cause of exploitable undefined
behavior, and memory-related undefined behavior has historically been the
cause of
[roughly 70% of Microsoft's disclosed CVEs](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends%2C%20challenge%2C%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf).
As a result, Microsoft designed a new set of "bounds-checking" C routines for
addressing memory unsafety in C, and these routines were added as Annex K to
ISO C11. Additionally, Microsoft added the non-bounds-checking versions of
these routines to a [list of banned functions](https://docs.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10)?redirectedfrom=MSDN)
as part of their Security Design Lifecycle. However, these bounds-checking
routines remain problematic and poorly adopted for several reasons:

* Calculation of the correct bounds for these routines must still be done
  manually, and in many uses, the use of the "bounds-checking" interface would
  involve simply passing the same static parameter to the interface twice,
  which provides no additional safety in practice.
* Even when using the Annex K routines, memory unsafety and other forms of
  undefined behavior are still frighteningly easy to trigger in C, and other
  tooling must still be used to detect these errors (such as static analyzers,
  compiler-based sanitizers, and
  [interpreter-based undefined behavior detectors](https://github.com/TrustInSoft/tis-interpreter),
  all of which have been applied to Sweet B).
* Bounds-checking interfaces are not implemented in most standard C libraries,
  and the use of a third-party library complicates the software supply chain
  by adding a dependency where none would otherwise exist.
  
Annex K has been [proposed for removal](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1967.htm)
from the next revision of the C standard, and while others have proposed
[revising and retaining](https://www.nccgroup.trust/us/our-research/bounds-checking-interfaces-field-experience-and-future-directions/)
its functionality, it seems clear that these interfaces will not be widely
supported in the near future.

As such, while bounds-checking interfaces could be optionally adopted
in Sweet B, it seems unlikely that they would provide any benefit to most
users unless the use of an additional third-party library is mandated. Given
our explicit goal of facilitating wide adoption in embedded and low-level
projects, this would be counterproductive. The authors believe that concerns
with memory unsafety in C are best addressed by eschewing the use of C
entirely except in specific contexts, and when C is used, through the use of
sanitizers and other mitigations in conjunction with extensive testing.

## TOB-SB-005: APIs for ECDSA signing and verification do not enforce secure hashing

This finding has been remediated in commit
[`e2e5de6`](https://github.com/westerndigitalcorporation/sweet-b/commit/e2e5de6777ac0850ffdeac73fa5d43439aec34b0)
by providing additional APIs as recommended which more completely encapsulate
the needed message digest step:

* a complete `sb_sha256_message` API, which produces a digest
  for an entire message;
* a complete `sb_hmac_sha256` API to parallel the `sb_sha256_message` API;
* a complete `sb_sw_sign_message_sha256` API, which takes an entire message
  as input and provides its signature and digest as output;
* a complete `sb_sw_verify_signature_sha256` API, which takes an entire
  message as input and verifies the signature while providing its digest;
* a `sb_sw_sign_message_sha256_start API`, which takes a `sb_sha256_state_t`
  and internally calls `sb_sha256_finish` to produce the message digest
  before starting incremental signing of the digest; and
* a corresponding `sb_sw_verify_signature_sha256_start` API.
  
The existing `sb_sw_sign_message_digest` signature has been retained for use
cases where the message is not available in one contiguous block of
memory and the message digest is needed in multiple contexts, but the other
signatures are be recommended for use over `sb_sw_sign_message_digest`.

## Non-security-related findings

These findings have been remediated in commit [`aae5c71`](https://github.com/westerndigitalcorporation/sweet-b/commit/aae5c713f87a0589f38a07bd3f41820ebf2e1e7a).

## Long-term recommendations

* Trail of Bits has recommended that we produce a user's guide detailing how
  to incorporate Sweet B into a project. This is an excellent idea and will
  be pursued after other findings have been remediated.
* Scanning for external dependencies (undefined symbols) in objects
  containing code that is intended it be constant time is a good idea, and
  could be straightforwardly automated.
* Elimination of the hardcoded offset that is relied upon by assembly is not
  a high priority if the correct offset is asserted at compile time. When
  debugging asserts are not enabled, this offset should be stable on all
  reasonable platforms, and alternative solutions would complicate
  cross-compilation.
* Additional hash functions are not planned in the near-term future, but
  more unit tests would certainly be added if new hash functions were
  incorporated.
  
## Additional unit testing

In Appendix C of the report, Trail of Bits provided an analysis of unit test
coverage and made several suggestions:

* One routine (`sb_fe_rshift`) in `sb_fe_tests.c.h` was uncovered. This was
  remediated by removing the routine in commit
  [`e2c4d98`](https://github.com/westerndigitalcorporation/sweet-b/commit/e2c4d9827b448f8bda753c2667b13ed1004e52aa).
* Error handling code in the HMAC_DRBG implementation was uncovered. This was
  remediated by adding an additional unit test in commit
  [`a6561da`](https://github.com/westerndigitalcorporation/sweet-b/commit/a6561daf8e7932ca8bb8b71ea8b1f9750b2c865d).
* Two edge cases in `sb_sw_lib.c` were uncovered. This was remediated by
  adding additional unit tests in commit
  [`0cc50e6`](https://github.com/westerndigitalcorporation/sweet-b/commit/0cc50e6f95e3d004d1e3d7875e963416378c23e1).
* A number of field-element routines in `sb_fe.c` are not covered directly;
  rather, they are covered by higher-level tests of curve operations. This
  will be remediated by adding additional unit tests.