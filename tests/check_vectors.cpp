// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// Vector check for every hash core in this project. Each table row is hashed
// twice: in a single update() call and in uneven pieces, so the buffering at
// block boundaries is exercised both ways.

#include "blake3_hash.hpp"
#include "hmac.hpp"
#include "keccak.hpp"
#include "kmac.hpp"
#include "ripemd160.hpp"
#include "sha512_hash.hpp"
#include "sm3_hash.hpp"
#include "sm4.hpp"
#include "vectors.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <string>
#include <vector>

// Official BLAKE3 test_vectors.json (hash mode), same test_vector shape.
#include "vectors.inc"

namespace
{
int failures = 0;

// The BLAKE3 test vectors use this 32-byte ASCII key; the SM4-CMAC rows use
// the key from the SM4 standard.
constexpr std::uint8_t blake3_test_key[32] = {
    'w', 'h', 'a', 't', 's', ' ', 't', 'h', 'e', ' ', 'E', 'l', 'v', 'i', 's', 'h',
    ' ', 'w', 'o', 'r', 'd', ' ', 'f', 'o', 'r', ' ', 'f', 'r', 'i', 'e', 'n', 'd'};
constexpr std::uint8_t sm4_test_key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                           0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
                                           0x76, 0x54, 0x32, 0x10};

std::string to_hex(const std::uint8_t *data, std::size_t len)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(2 * len);
    for (std::size_t i = 0; i < len; ++i)
    {
        hex.push_back(digits[data[i] >> 4]);
        hex.push_back(digits[data[i] & 0x0f]);
    }
    return hex;
}

std::vector<std::uint8_t> make_input(std::size_t len)
{
    std::vector<std::uint8_t> input(len);
    for (std::size_t i = 0; i < len; ++i)
        input[i] = static_cast<std::uint8_t>(i % 251);
    return input;
}

template <typename Hasher>
void feed(Hasher &hasher, const std::uint8_t *data, std::size_t len,
          bool chunked)
{
    if (!chunked)
    {
        hasher.update(data, len);
        return;
    }
    std::size_t offset = 0;
    std::size_t step = 1;
    while (offset < len)
    {
        std::size_t take = step;
        if (take > len - offset)
            take = len - offset;
        hasher.update(data + offset, take);
        offset += take;
        step = step * 7 % 5000 + 1;
    }
}

template <typename Hasher> std::string digest_hex(Hasher &hasher)
{
    const auto digest = hasher.finalize();
    return to_hex(digest.data(), digest.size());
}

template <typename MakeHasher>
void check_table(const char *name, MakeHasher make, const test_vector *rows,
                 std::size_t count)
{
    for (std::size_t i = 0; i < count; ++i)
    {
        const std::vector<std::uint8_t> input = make_input(rows[i].input_len);
        for (const bool chunked : {false, true})
        {
            auto hasher = make();
            feed(hasher, input.data(), input.size(), chunked);
            const std::string got = digest_hex(hasher);
            if (got == rows[i].hex)
                continue;
            ++failures;
            std::printf("FAIL %s len=%zu (%s)\n  got %s\n  exp %s\n", name,
                        rows[i].input_len, chunked ? "chunked" : "one-shot",
                        got.c_str(), rows[i].hex);
        }
    }
}

template <typename MakeHasher>
void check_message(const char *name, MakeHasher make, const std::string &message,
                   const char *expected)
{
    auto hasher = make();
    hasher.update(reinterpret_cast<const std::uint8_t *>(message.data()),
                  message.size());
    const std::string got = digest_hex(hasher);
    if (got == expected)
        return;
    ++failures;
    std::printf("FAIL %s\n  got %s\n  exp %s\n", name, got.c_str(), expected);
}
} // namespace

int main()
{
    check_table("blake3", [] { return b3::hasher{}; }, vectors,
                std::size(vectors));
    check_table("sm3", [] { return sm3::hasher{}; }, sm3_vectors,
                std::size(sm3_vectors));
    check_table("sha512_256", [] { return sha512_256::hasher{}; },
                sha512_256_vectors, std::size(sha512_256_vectors));
    check_table("sha3_224", [] { return keccak::sponge<144, 28>{}; },
                sha3_224_vectors, std::size(sha3_224_vectors));
    check_table("sha3_384", [] { return keccak::sponge<104, 48>{}; },
                sha3_384_vectors, std::size(sha3_384_vectors));
    check_table("hmac_sm3",
                [] { return sm3::hmac::hasher(hmac_key); },
                hmac_sm3_vectors, std::size(hmac_sm3_vectors));
    check_table("keccak256", [] { return keccak::sponge<136, 32, 0x01>{}; },
                keccak256_vectors, std::size(keccak256_vectors));
    check_table("sha512_224", [] { return sha512_224::hasher{}; },
                sha512_224_vectors, std::size(sha512_224_vectors));
    check_table("hmac_sha512_256",
                [] {
                    return provider_common::hmac<sha512_256::hasher,
                                                 sha512::block_len>(hmac_key);
                },
                hmac_sha512_256_vectors, std::size(hmac_sha512_256_vectors));
    check_table("hmac_sha512_224",
                [] {
                    return provider_common::hmac<sha512_224::hasher,
                                                 sha512::block_len>(hmac_key);
                },
                hmac_sha512_224_vectors, std::size(hmac_sha512_224_vectors));
    check_table("keccak512", [] { return keccak::sponge<72, 64, 0x01>{}; },
                keccak512_vectors, std::size(keccak512_vectors));
    check_table("shake128_256", [] { return keccak::sponge<168, 32, 0x1f>{}; },
                shake128_256_vectors, std::size(shake128_256_vectors));
    check_table("shake256_512", [] { return keccak::sponge<136, 64, 0x1f>{}; },
                shake256_512_vectors, std::size(shake256_512_vectors));
    check_table("kmac128",
                [] { return provider_common::kmac<168, 32>(hmac_key); },
                kmac128_vectors, std::size(kmac128_vectors));
    check_table("kmac256",
                [] { return provider_common::kmac<136, 64>(hmac_key); },
                kmac256_vectors, std::size(kmac256_vectors));
    check_table("blake3_keyed", [] { return b3::hasher(blake3_test_key); },
                blake3_keyed_vectors, std::size(blake3_keyed_vectors));
    check_table("ripemd160", [] { return ripemd160::hasher{}; },
                ripemd160_vectors, std::size(ripemd160_vectors));
    check_table("sm4_cmac", [] { return sm4::cmac(sm4_test_key); },
                sm4_cmac_vectors, std::size(sm4_cmac_vectors));

    // Published known-answer tests, independent of the generated tables.
    const std::string abc = "abc";
    check_message(
        "sm3(abc)", [] { return sm3::hasher{}; }, abc,
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    check_message("sm3(abcd x16)", [] { return sm3::hasher{}; },
                  std::string("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
                              "abcdabcdabcd"),
                  "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
    check_message(
        "hmac_sm3(key, abc)",
        [] { return sm3::hmac::hasher("key"); }, abc,
        "28e63256e7c5a087b1f073265dc53092163f7b82729735d06f28f10af9d52393");
    check_message(
        "keccak256(abc)", [] { return keccak::sponge<136, 32, 0x01>{}; }, abc,
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    check_message(
        "sha512_224(abc)", [] { return sha512_224::hasher{}; }, abc,
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    check_message(
        "hmac_sha512_256(key, abc)",
        [] {
            return provider_common::hmac<sha512_256::hasher,
                                         sha512::block_len>("key");
        },
        abc,
        "f367b7ca80ab2cf85c23e58b73a8fd525a6fa2c66ff105804a2d4cf4df06e129");
    check_message(
        "hmac_sha512_224(key, abc)",
        [] {
            return provider_common::hmac<sha512_224::hasher,
                                         sha512::block_len>("key");
        },
        abc, "28bc0433ef684ea9877c2f2437aa0ccfc2e8eb3a9b4c731606877b4f");
    check_message(
        "sha512(abc)", [] { return sha512::hasher{}; }, abc,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a"
        "3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    check_message(
        "sha512_256(abc)", [] { return sha512_256::hasher{}; }, abc,
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    check_message("sha3_224(abc)", [] { return keccak::sponge<144, 28>{}; }, abc,
                  "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    check_message("sha3_384(abc)", [] { return keccak::sponge<104, 48>{}; }, abc,
                  "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
                  "98d88cea927ac7f539f1edf228376d25");
    check_message(
        "keccak512(abc)", [] { return keccak::sponge<72, 64, 0x01>{}; }, abc,
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96");
    check_message(
        "shake128_256(abc)", [] { return keccak::sponge<168, 32, 0x1f>{}; },
        abc, "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
    check_message(
        "shake256_512(abc)", [] { return keccak::sponge<136, 64, 0x1f>{}; },
        abc,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
    check_message(
        "kmac128(tsubaki, abc)",
        [] { return provider_common::kmac<168, 32>(hmac_key); }, abc,
        "95207afe1b851f2d823c79506441aae70a4248180541e6ec946cb2507429aa64");
    check_message(
        "kmac256(tsubaki, abc)",
        [] { return provider_common::kmac<136, 64>(hmac_key); }, abc,
        "b76ca775a95ffaa8d95fd9072d2bb6af66e7b35f6c0835ae795c16e4d070dae2eeba18178cafaae2dc8513fe2a2e4430a235a749ceb40a0c67d8670de25c41b3");
    check_message(
        "blake3_keyed(empty)", [] { return b3::hasher(blake3_test_key); },
        "",
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26");
    check_message(
        "ripemd160(abc)", [] { return ripemd160::hasher{}; }, abc,
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    check_message(
        "sm4_cmac(key, abc)", [] { return sm4::cmac(sm4_test_key); }, abc,
        "8e75238ac2672a6aee408c1e251854d8");

    if (failures != 0)
    {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }
    std::printf("all vectors match\n");
    return 0;
}
