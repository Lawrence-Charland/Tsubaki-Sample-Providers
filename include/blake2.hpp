// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// BLAKE2b and BLAKE2s (RFC 7693) with the parameter block exposed: the digest
// length, a 16-byte salt and a 16-byte personalization string. Those three are
// what a provider needs on top of the built-in blake2b512/blake2s256, which
// fix them to their defaults. Keying stays with the built-in *_mac algorithms.
//
// Both widths are one template: they differ only in word size, block size,
// rotation constants and round count, so the compression function is shared.

#ifndef TSUBAKI_PROVIDER_BLAKE2_HPP
#define TSUBAKI_PROVIDER_BLAKE2_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace provider_common
{
template <typename Word> struct blake2_traits;

template <> struct blake2_traits<std::uint64_t>
{
    static constexpr std::size_t block_bytes = 128;
    static constexpr unsigned rounds = 12;
    static constexpr unsigned rot1 = 32, rot2 = 24, rot3 = 16, rot4 = 63;
    static constexpr std::array<std::uint64_t, 8> iv = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
        0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
        0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
    static constexpr std::size_t max_out = 64;
};

template <> struct blake2_traits<std::uint32_t>
{
    static constexpr std::size_t block_bytes = 64;
    static constexpr unsigned rounds = 10;
    static constexpr unsigned rot1 = 16, rot2 = 12, rot3 = 8, rot4 = 7;
    static constexpr std::array<std::uint32_t, 8> iv = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    static constexpr std::size_t max_out = 32;
};

template <typename Word> class blake2
{
  private:
    using traits = blake2_traits<Word>;

    static Word rotate_right(Word x, unsigned n) noexcept
    {
        return (x >> n) | (x << (8 * sizeof(Word) - n));
    }

    static Word read_word(const std::uint8_t *p) noexcept
    {
        Word value = 0;
        for (std::size_t i = 0; i < sizeof(Word); ++i)
            value |= Word(p[i]) << (8 * i);
        return value;
    }

    static void mix(Word v[16], unsigned a, unsigned b, unsigned c, unsigned d,
                    Word x, Word y) noexcept
    {
        v[a] = v[a] + v[b] + x;
        v[d] = rotate_right(v[d] ^ v[a], traits::rot1);
        v[c] = v[c] + v[d];
        v[b] = rotate_right(v[b] ^ v[c], traits::rot2);
        v[a] = v[a] + v[b] + y;
        v[d] = rotate_right(v[d] ^ v[a], traits::rot3);
        v[c] = v[c] + v[d];
        v[b] = rotate_right(v[b] ^ v[c], traits::rot4);
    }

    static const std::uint8_t *sigma() noexcept
    {
        static constexpr std::uint8_t table[10][16] = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
        return &table[0][0];
    }

    std::array<Word, 8> h_{};
    std::uint64_t t_low_ = 0;
    std::uint64_t t_high_ = 0;
    std::array<std::uint8_t, traits::block_bytes> buffer_{};
    std::size_t buffer_len_ = 0;
    std::size_t out_len_ = 0;

    void add_counter(std::size_t bytes) noexcept
    {
        const std::uint64_t previous = t_low_;
        t_low_ += bytes;
        if (t_low_ < previous)
            ++t_high_;
    }

    void compress(bool last) noexcept
    {
        std::array<Word, 16> m{};
        for (std::size_t i = 0; i < 16; ++i)
            m[i] = read_word(buffer_.data() + i * sizeof(Word));

        Word v[16];
        for (std::size_t i = 0; i < 8; ++i)
            v[i] = h_[i];
        for (std::size_t i = 0; i < 8; ++i)
            v[8 + i] = traits::iv[i];
        v[12] ^= static_cast<Word>(t_low_);
        v[13] ^= static_cast<Word>(t_high_);
        if (last)
            v[14] = static_cast<Word>(~v[14]);

        const std::uint8_t *s = sigma();
        for (unsigned round = 0; round < traits::rounds; ++round)
        {
            const std::uint8_t *r = s + (round % 10) * 16;
            mix(v, 0, 4, 8, 12, m[r[0]], m[r[1]]);
            mix(v, 1, 5, 9, 13, m[r[2]], m[r[3]]);
            mix(v, 2, 6, 10, 14, m[r[4]], m[r[5]]);
            mix(v, 3, 7, 11, 15, m[r[6]], m[r[7]]);
            mix(v, 0, 5, 10, 15, m[r[8]], m[r[9]]);
            mix(v, 1, 6, 11, 12, m[r[10]], m[r[11]]);
            mix(v, 2, 7, 8, 13, m[r[12]], m[r[13]]);
            mix(v, 3, 4, 9, 14, m[r[14]], m[r[15]]);
        }
        for (std::size_t i = 0; i < 8; ++i)
            h_[i] ^= v[i] ^ v[8 + i];
    }

  public:
    blake2(std::size_t out_len, const std::array<std::uint8_t, 16> &salt = {},
           const std::array<std::uint8_t, 16> &personal = {})
        : out_len_(out_len > traits::max_out ? traits::max_out : out_len)
    {
        h_ = traits::iv;
        // RFC 7693 section 2.5: digest length, key length (zero here), fanout
        // and depth all live in the first word of the parameter block.
        h_[0] ^= Word(0x01010000) ^ Word(out_len_);
        for (std::size_t i = 0; i < 2; ++i)
        {
            h_[4 + i] ^= read_word(salt.data() + i * sizeof(Word));
            h_[6 + i] ^= read_word(personal.data() + i * sizeof(Word));
        }
    }

    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        if (input_len == 0)
            return;

        while (input_len > 0)
        {
            if (buffer_len_ == traits::block_bytes)
            {
                // The counter covers the bytes compressed so far, not the
                // whole message: a block is only final once it leaves the
                // buffer.
                add_counter(buffer_len_);
                compress(false);
                buffer_len_ = 0;
            }
            const std::size_t take =
                input_len < traits::block_bytes - buffer_len_
                    ? input_len
                    : traits::block_bytes - buffer_len_;
            std::memcpy(buffer_.data() + buffer_len_, input, take);
            buffer_len_ += take;
            input += take;
            input_len -= take;
        }
    }

    std::vector<std::uint8_t> finalize() const
    {
        blake2 copy = *this;
        copy.add_counter(copy.buffer_len_);
        for (std::size_t i = copy.buffer_len_; i < traits::block_bytes; ++i)
            copy.buffer_[i] = 0;
        copy.compress(true);

        std::vector<std::uint8_t> out(copy.out_len_);
        for (std::size_t i = 0; i < copy.out_len_; ++i)
            out[i] = static_cast<std::uint8_t>(copy.h_[i / sizeof(Word)] >>
                                               (8 * (i % sizeof(Word))));
        return out;
    }
};

using blake2b = blake2<std::uint64_t>;
using blake2s = blake2<std::uint32_t>;
} // namespace provider_common

#endif
