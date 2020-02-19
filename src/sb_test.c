/** @file sb_test.c
 *  @brief test driver for Sweet B tests
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

#include "sb_test.h"

#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#ifdef SB_TEST

_Bool sb_test_assert_failed(const char* const file, const char* const line,
                            const char* const expression)
{
    printf("\n%s:%s: failed assertion: %s\n", file, line, expression);
    return 0;
}

static int usage(const char* procname)
{
    printf("Usage: %s [-c count] [-t test]\n", procname);
    printf("\tIf -t is supplied, the test is run for count iterations.\n");
    printf("\tIf -c is not supplied, count defaults to "
               SB_TEST_STRINGIFY(SB_TEST_ITER_DEFAULT) "\n");
    return 1;
}

#ifdef SB_TEST_TIS
int main(void)
#else
int main(const int argc, char** const argv)
#endif
{
    int option;
    uintmax_t test_iter = SB_TEST_ITER_DEFAULT;
    _Bool test_iter_supplied = 0;
    const char* test_iter_match = NULL;
#ifdef SB_TEST_TIS
    const char* prog = "sb_test";
#define fflush(v) do { } while (0)
#else
    const char* prog = argv[0];
    while ((option = getopt(argc, argv, "t:c:")) >= 0) {
        switch (option) {
            case 't': {
                test_iter_match = optarg;
                continue;
            }
            case 'c': {
                char* end;
                test_iter = strtoumax(optarg, &end, 10);
                if (*optarg == 0 || *end != 0) {
                    return usage(prog);
                }
                test_iter_supplied = 1;
                continue;
            }
            default: {
                printf("%s: unknown option %c\n", prog, option);
                return usage(prog);
            }
        }
    }

    if (optind != argc) {
        return usage(prog);
    }
#endif

    if (test_iter_supplied && test_iter_match == NULL) {
        printf("%s: -t must be supplied if -c is supplied!\n", prog);
        return usage(prog);
    }

    uint32_t test_count = 0;
    uint32_t test_passed = 0;

    if (test_iter_match == NULL) {

#define SB_TEST_IMPL

#define SB_DEFINE_TEST(name) do { \
    printf("test " #name "... "); \
    fflush(NULL); \
    test_count++; \
    if (sb_test_ ## name()) { \
        printf("passed!\n"); \
        test_passed++; \
    } else { \
        printf("failed!\n"); \
    } \
} while (0)

        printf("Running tests:\n");
#include "sb_test_list.h"
#undef SB_DEFINE_TEST

        printf("%" PRIu32 "/%" PRIu32 " tests passed\n", test_passed,
               test_count);
        if (test_passed != test_count) {
            return 1;
        }
    } else {
        _Bool (* test_iter_fn)(void) = NULL;
#define SB_DEFINE_TEST(name) do { \
    if (strlen(test_iter_match) == strlen(SB_TEST_STRINGIFY(name)) && \
        strcmp(test_iter_match, SB_TEST_STRINGIFY(name)) == 0) { \
            test_iter_fn = sb_test_ ## name; \
    } \
} while (0)

#include "sb_test_list.h"

        if (test_iter_fn == NULL) {
            printf("%s: unknown test name %s\n", prog, test_iter_match);
            return usage(prog);
        }

        printf("Running %s for %" PRIuMAX " iterations... ", test_iter_match,
               test_iter);
        fflush(NULL);

        for (uintmax_t i = 0; i < test_iter; i++) {
            if (test_iter_fn() != 1) {
                printf("failed!\n");
                return 1;
            }
        }
        printf("passed!\n");
    }
    return 0;
}

#endif
