# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)
project(tsubaki-providers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The contract header is part of the tsubaki source tree; point this at the
# include/ directory that holds dynamic_provider_header.hpp. Nothing else here
# depends on where tsubaki lives.
set(TSUBAKI_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
    CACHE PATH "Directory holding dynamic_provider_header.hpp")
if(NOT EXISTS "${TSUBAKI_INCLUDE_DIR}/dynamic_provider_header.hpp")
    message(FATAL_ERROR
        "dynamic_provider_header.hpp was not found in ${TSUBAKI_INCLUDE_DIR}. "
        "Set -DTSUBAKI_INCLUDE_DIR=<tsubaki>/include to the tree these modules "
        "are built against.")
endif()

# Every module lands directly in the build directory, so a single
# TSUBAKI_DYNAMIC_PROVIDER_PATHS entry covers the whole set.
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# tsubaki only loads files whose extension is exactly .so and it does not strip
# a "lib" prefix, so the output name has to be the algorithm name itself.
function(tsubaki_provider name)
    add_library(${name} MODULE ${ARGN})
    target_include_directories(${name} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${TSUBAKI_INCLUDE_DIR}")
    set_target_properties(${name} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${name}"
        CXX_VISIBILITY_PRESET default)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra)
    endif()
endfunction()

tsubaki_provider(blake3      blake3/blake3.cpp)
tsubaki_provider(sm3         sm3/sm3.cpp)
tsubaki_provider(hmac_sm3    sm3/hmac_sm3.cpp)
tsubaki_provider(sha512_256  sha512_256/sha512_256.cpp)
tsubaki_provider(sha3_224    sha3/sha3_224.cpp)
tsubaki_provider(sha3_384    sha3/sha3_384.cpp)

# Vector check: cmake --build <dir> && ctest --test-dir <dir> --output-on-failure
enable_testing()
add_executable(check_vectors tests/check_vectors.cpp)
target_include_directories(check_vectors PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/blake3"
    "${CMAKE_CURRENT_SOURCE_DIR}/sha3"
    "${CMAKE_CURRENT_SOURCE_DIR}/sha512_256"
    "${CMAKE_CURRENT_SOURCE_DIR}/sm3")
target_compile_options(check_vectors PRIVATE -Wall -Wextra)
add_test(NAME provider_vectors COMMAND check_vectors)
