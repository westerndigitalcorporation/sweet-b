// swift-tools-version:5.5

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is part of Sweet B, a safe, compact, embeddable library for
 * elliptic curve cryptography.
 *
 * https://github.com/westerndigitalcorporation/sweet-b
 *
 * Copyright (c) 2022 Western Digital Corporation or its affiliates.
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

import PackageDescription

/*
 Building Sweet B as a Swift package makes it easy to use Sweet B routines
 from Swift.  It isn't necessary to fuss around with a modulemap file, or
 add individual files from Sweet B to your target.

 After adding this package to your target's dependencies, you can write
 stuff like this:

 import SweetB

 let salt: [sb_byte_t] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0A, 0x0B, 0x0C]
 let ikm: [sb_byte_t] = [0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
                         0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
                         0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B]

 var hkdf = sb_hkdf_state_t()
 sb_hkdf_extract(&hkdf, salt, salt.count, ikm, ikm.count)

 When using this as a local package, select your Xcode target's General tab,
 and add the package to the Frameworks and Libraries section.
 */

let package = Package(
    name: "SweetB",
    products: [
        .library(name: "SweetB", targets: ["SweetB"])
    ],
    targets: [
        .target(
            name: "SweetB",
            path: ".",
            sources: [
                "src/sb_sha256.c",
                "src/sb_hmac_sha256.c",
                "src/sb_hmac_drbg.c",
                "src/sb_hkdf.c",
                "src/sb_fe.c",
                "src/sb_sw_lib.c"
            ],
            publicHeadersPath: "include"
        )
    ]
)
