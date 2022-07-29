#
# CMakeLists.txt: abandon all hope, etc etc etc
#
# SPDX-License-Identifier: BSD-3-Clause
#
# This file is part of Sweet B, a safe, compact, embeddable library for
# elliptic curve cryptography.
#
# https://github.com/westerndigitalcorporation/sweet-b
#
# Copyright (c) 2020-2021 Western Digital Corporation or its affiliates.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

cmake_minimum_required(VERSION 3.5)

project(sweet_b LANGUAGES C ASM VERSION 0.1.0)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)

if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
        "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    message(STATUS "Enabling clang options")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything -Wno-padded -Wno-c++98-compat -Wno-documentation-unknown-command")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined -fsanitize=address")
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_POSIX_C_SOURCE=200112L -Wall -pedantic -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")

include_directories(include)

set(SB_PUBLIC_HEADERS
        include/sb_sw_lib.h
        include/sb_hmac_drbg.h
        include/sb_hmac_sha256.h
        include/sb_hkdf.h
        include/sb_sha256.h
        include/sb_sw_context.h
        include/sb_types.h
        include/sb_all.h)

set(SB_PRIVATE_HEADERS
        src/sb_error.h
        src/sb_fe.h
        src/sb_fe_tests.c.h
        src/sb_sw_curves.h
        src/sb_sw_lib_tests.c.h
        src/sb_test.h
        src/sb_test_cavp.h
        src/sb_test_list.h)

set(SB_ASM_SOURCES)

if(NOT DEFINED SB_FE_ASM)
    set(SB_FE_ASM "0" CACHE STRING "")
endif()

set(SB_SOURCES
        ${SB_PUBLIC_HEADERS}
        ${SB_PRIVATE_HEADERS}
        ${SB_ASM_SOURCES}

        src/sb_sha256.c
        src/sb_hmac_sha256.c
        src/sb_hmac_drbg.c
        src/sb_hkdf.c

        src/sb_fe.c
        src/sb_sw_lib.c
        
        wycheproof/sb_wycheproof_ecdh_test.c
        wycheproof/sb_wycheproof_ecdsa_test.c
        wycheproof/sb_wycheproof_hmac_test.c)

if(NOT DEFINED SB_TEST)
    option(SB_TEST "" ON)
endif()

if(SB_TEST)
    set_property(SOURCE src/sb_test.c APPEND PROPERTY OBJECT_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/src/sb_test_list.h")

    add_executable(sb_test ${SB_SOURCES} src/sb_test.c src/sb_test_cavp.c)

    # 16x16->32 operations are most likely to accidentally trigger UB if there is
    # a missing cast from implicitly promoted int to uint32_t

    # If you update the SB_HMAC_DRBG options here to make unit tests pass, you
    # must also update the checks in sb_hmac_drbg.h

    if(NOT DEFINED SB_TEST_WORD_SIZE)
        set(SB_TEST_WORD_SIZE "2" CACHE STRING "")
    endif()

    if(NOT DEFINED SB_TIME)
        set(SB_TIME "0" CACHE STRING "")
    endif()

    if(SB_TIME)
        set(SB_TEST_VERIFY_QR "0" CACHE STRING "")
    endif()

    if(NOT DEFINED SB_TEST_VERIFY_QR)
        set(SB_TEST_VERIFY_QR "1" CACHE STRING "")
    endif()

    target_compile_definitions(sb_test PRIVATE
            SB_TEST
            SB_WORD_SIZE=${SB_TEST_WORD_SIZE}
            SB_FE_VERIFY_QR=${SB_TEST_VERIFY_QR}
            SB_FE_ASM=${SB_FE_ASM}
            SB_TIME=${SB_TIME}
            SB_UNROLL=3
            SB_HMAC_DRBG_RESEED_INTERVAL=18
            SB_HMAC_DRBG_MAX_BYTES_PER_REQUEST=128
            SB_HMAC_DRBG_MAX_ENTROPY_INPUT_LENGTH=256)

    enable_testing()

    add_test(NAME sb_test
            CONFIGURATIONS Debug
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            COMMAND sb_test)
endif(SB_TEST)

if(NOT DEFINED BUILD_SHARED_LIBS)
    option(BUILD_SHARED_LIBS "" ON)
endif()

add_library(sweet_b ${SB_SOURCES})

if(NOT DEFINED SB_LIBRARY_DEFINES)
    set(SB_LIBRARY_DEFINES "" CACHE STRING "")
endif()

target_compile_definitions(sweet_b PRIVATE
        ${SB_LIBRARY_DEFINES}
        SB_FE_ASM=${SB_FE_ASM})

target_include_directories(sweet_b INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

set_target_properties(sweet_b PROPERTIES
        VERSION ${PROJECT_VERSION}
        PUBLIC_HEADER "${SB_PUBLIC_HEADERS}")

install(TARGETS sweet_b
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
