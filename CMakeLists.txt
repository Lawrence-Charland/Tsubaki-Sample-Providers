# SPDX-License-Identifier: GPL-2.0-only
# Helped by DeepSeek

cmake_minimum_required(VERSION 3.16)
project(tsubaki-providers LANGUAGES CXX)

# Same platform floor as tsubaki itself: the providers read files with
# fcntl.h/unistd.h and are dlopen'd, so they target POSIX systems only.
if(WIN32 AND NOT CYGWIN)
    message(FATAL_ERROR
        "tsubaki-providers target POSIX systems only (fcntl.h, unistd.h). "
        "Native Windows is not supported; build under Cygwin or WSL instead.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The contract header ships here as a copy of tsubaki's. Point
# -DTSUBAKI_INCLUDE_DIR=<tsubaki>/include to build the same sources against
# that tree instead of this copy.
set(TSUBAKI_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include"
    CACHE PATH "Directory holding dynamic_provider_header.hpp")
if(NOT EXISTS "${TSUBAKI_INCLUDE_DIR}/dynamic_provider_header.hpp")
    message(FATAL_ERROR
        "dynamic_provider_header.hpp was not found in ${TSUBAKI_INCLUDE_DIR}. "
        "Set -DTSUBAKI_INCLUDE_DIR to a directory that holds it.")
endif()

# Every module lands directly in the build directory, so a single
# TSUBAKI_DYNAMIC_PROVIDER_PATHS entry covers the whole set.
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# tsubaki only loads files whose extension is exactly .so and it does not strip
# a "lib" prefix, so the output name has to be the algorithm name itself.
function(tsubaki_provider name)
    add_library(${name} MODULE ${ARGN})
    # TSUBAKI_INCLUDE_DIR comes first so an external tsubaki tree, when given,
    # supplies the contract header instead of our copy in include/.
    target_include_directories(${name} PRIVATE
        "${TSUBAKI_INCLUDE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/include")
    set_target_properties(${name} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${name}"
        CXX_VISIBILITY_PRESET default)
    # On Cygwin a MODULE library is a .dll, but tsubaki only dlopen's files
    # named *.so. Linux, macOS and the BSDs already produce .so here.
    if(CYGWIN)
        set_target_properties(${name} PROPERTIES SUFFIX ".so")
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra)
    endif()
endfunction()

# Unkeyed digests.
tsubaki_provider(blake3      src/hash/blake3.cpp)
tsubaki_provider(keccak224   src/hash/keccak224.cpp)
tsubaki_provider(keccak256   src/hash/keccak256.cpp)
tsubaki_provider(keccak384   src/hash/keccak384.cpp)
tsubaki_provider(keccak512   src/hash/keccak512.cpp)
tsubaki_provider(shake128_256 src/hash/shake128_256.cpp)
tsubaki_provider(shake256_512 src/hash/shake256_512.cpp)
tsubaki_provider(turboshake128_256 src/hash/turboshake128_256.cpp)
tsubaki_provider(turboshake256_512 src/hash/turboshake256_512.cpp)
tsubaki_provider(kt128       src/hash/kt128.cpp)
tsubaki_provider(kt256       src/hash/kt256.cpp)
tsubaki_provider(ripemd160   src/hash/ripemd160.cpp)
tsubaki_provider(sha512_224  src/hash/sha512_224.cpp)
tsubaki_provider(sha512_256  src/hash/sha512_256.cpp)
tsubaki_provider(sm3         src/hash/sm3.cpp)
tsubaki_provider(sha3_224    src/hash/sha3_224.cpp)
tsubaki_provider(sha3_384    src/hash/sha3_384.cpp)

# Keyed / MAC constructions.
tsubaki_provider(blake3_keyed src/mac/blake3_keyed.cpp)
tsubaki_provider(kmac128     src/mac/kmac128.cpp)
tsubaki_provider(kmac256     src/mac/kmac256.cpp)
tsubaki_provider(hmac_sm3    src/mac/hmac_sm3.cpp)
tsubaki_provider(hmac_sha512_224 src/mac/hmac_sha512_224.cpp)
tsubaki_provider(hmac_sha512_256 src/mac/hmac_sha512_256.cpp)
tsubaki_provider(sm4_cmac    src/mac/sm4_cmac.cpp)
tsubaki_provider(aes_cmac    src/mac/aes_cmac.cpp)
tsubaki_provider(seed_cmac   src/mac/seed_cmac.cpp)
tsubaki_provider(aria_cmac   src/mac/aria_cmac.cpp)
tsubaki_provider(camellia_cmac src/mac/camellia_cmac.cpp)

# Vector check: cmake --build <dir> && ctest --test-dir <dir> --output-on-failure
enable_testing()
add_executable(check_vectors tests/check_vectors.cpp)
target_include_directories(check_vectors PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests")
target_compile_options(check_vectors PRIVATE -Wall -Wextra)
add_test(NAME provider_vectors COMMAND check_vectors)
