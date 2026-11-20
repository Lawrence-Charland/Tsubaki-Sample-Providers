// SPDX-License-Identifier: GPL-2.0-only

// Vector check for every hash core in this project. Each table row is hashed
// twice: in a single update() call and in uneven pieces, so the buffering at
// block boundaries is exercised both ways.

#include "blake3_hash.hpp"
#include "keccak.hpp"
#include "sha512_hash.hpp"
#include "sm3_hash.hpp"
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
                [] { return sm3::hmac::hasher(hmac_sm3_key); },
                hmac_sm3_vectors, std::size(hmac_sm3_vectors));

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

    if (failures != 0)
    {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }
    std::printf("all vectors match\n");
    return 0;
}
