// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// RIPEMD-160 (ISO/IEC 10118-3, 20-byte digest). Little-endian words, two
// parallel lines of 80 steps that exchange state at the end.

#ifndef TSUBAKI_PROVIDER_RIPEMD160_HPP
#define TSUBAKI_PROVIDER_RIPEMD160_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace ripemd160
{
inline constexpr std::size_t block_len = 64;
inline constexpr std::size_t digest_len = 20;
using digest_t = std::array<std::uint8_t, digest_len>;

inline std::uint32_t rol(std::uint32_t x, unsigned n) noexcept
{
    return (x << n) | (x >> (32u - n));
}

// Message word order, left and right lines.
inline constexpr unsigned rl[80] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    7,  4,  13, 1,  10, 6,  15, 3,  12, 0,  9,  5,  2,  14, 11, 8,
    3,  10, 14, 4,  9,  15, 8,  1,  2,  7,  0,  6,  13, 11, 5,  12,
    1,  9,  11, 10, 0,  8,  12, 4,  13, 3,  7,  15, 14, 5,  6,  2,
    4,  0,  5,  9,  7,  12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13};

inline constexpr unsigned rr[80] = {
    5,  14, 7,  0,  9,  2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7,  0,  13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3,  7,  14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1,  3,  11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4,  1,  5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};

inline constexpr unsigned sl[80] = {
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};

inline constexpr unsigned sr[80] = {
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};

// The two lines use the same five constants in opposite order.
inline constexpr std::uint32_t kl[5] = {0x00000000, 0x5a827999, 0x6ed9eba1,
                                        0x8f1bbcdc, 0xa953fd4e};
inline constexpr std::uint32_t kr[5] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3,
                                        0x7a6d76e9, 0x00000000};

inline std::uint32_t f(unsigned j, std::uint32_t x, std::uint32_t y,
                       std::uint32_t z) noexcept
{
    switch (j / 16)
    {
    case 0:
        return x ^ y ^ z;
    case 1:
        return (x & y) | (~x & z);
    case 2:
        return (x | ~y) ^ z;
    case 3:
        return (x & z) | (y & ~z);
    default:
        return x ^ (y | ~z);
    }
}

class hasher
{
  private:
    std::uint32_t h_[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                           0xc3d2e1f0u};
    std::array<std::uint8_t, block_len> buf_{};
    std::size_t buf_len_ = 0;
    std::uint64_t total_ = 0;

    void compress(const std::uint8_t *block) noexcept
    {
        std::uint32_t x[16];
        for (std::size_t i = 0; i < 16; ++i)
        {
            const std::size_t at = 4 * i;
            x[i] = static_cast<std::uint32_t>(block[at]) |
                   static_cast<std::uint32_t>(block[at + 1]) << 8 |
                   static_cast<std::uint32_t>(block[at + 2]) << 16 |
                   static_cast<std::uint32_t>(block[at + 3]) << 24;
        }

        std::uint32_t al = h_[0], bl = h_[1], cl = h_[2], dl = h_[3],
                      el = h_[4];
        std::uint32_t ar = h_[0], br = h_[1], cr = h_[2], dr = h_[3],
                      er = h_[4];

        for (unsigned j = 0; j < 80; ++j)
        {
            std::uint32_t t = rol(al + f(j, bl, cl, dl) + x[rl[j]] + kl[j / 16],
                                  sl[j]) +
                              el;
            al = el;
            el = dl;
            dl = rol(cl, 10);
            cl = bl;
            bl = t;

            t = rol(ar + f(79 - j, br, cr, dr) + x[rr[j]] + kr[j / 16], sr[j]) +
                er;
            ar = er;
            er = dr;
            dr = rol(cr, 10);
            cr = br;
            br = t;
        }

        const std::uint32_t t = h_[1] + cl + dr;
        h_[1] = h_[2] + dl + er;
        h_[2] = h_[3] + el + ar;
        h_[3] = h_[4] + al + br;
        h_[4] = h_[0] + bl + cr;
        h_[0] = t;
    }

  public:
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        total_ += input_len;
        if (buf_len_ > 0)
        {
            const std::size_t take =
                std::min(block_len - buf_len_, input_len);
            std::copy(input, input + take, buf_.begin() + buf_len_);
            buf_len_ += take;
            input += take;
            input_len -= take;
            if (buf_len_ == block_len)
            {
                compress(buf_.data());
                buf_len_ = 0;
            }
        }
        while (input_len >= block_len)
        {
            compress(input);
            input += block_len;
            input_len -= block_len;
        }
        if (input_len > 0)
        {
            std::copy(input, input + input_len, buf_.begin());
            buf_len_ = input_len;
        }
    }

    digest_t finalize() const noexcept
    {
        std::array<std::uint8_t, 2 * block_len> tail{};
        std::copy(buf_.begin(), buf_.begin() + buf_len_, tail.begin());
        tail[buf_len_] = 0x80;
        const std::size_t tail_len =
            buf_len_ < block_len - 8 ? block_len : 2 * block_len;
        const std::uint64_t bits = total_ * 8;
        for (std::size_t i = 0; i < 8; ++i)
            tail[tail_len - 8 + i] =
                static_cast<std::uint8_t>(bits >> (8 * i));

        hasher copy = *this;
        copy.compress(tail.data());
        if (tail_len == 2 * block_len)
            copy.compress(tail.data() + block_len);

        digest_t digest{};
        for (std::size_t i = 0; i < 5; ++i)
            for (std::size_t b = 0; b < 4; ++b)
                digest[4 * i + b] =
                    static_cast<std::uint8_t>(copy.h_[i] >> (8 * b));
        return digest;
    }
};
} // namespace ripemd160

#endif
