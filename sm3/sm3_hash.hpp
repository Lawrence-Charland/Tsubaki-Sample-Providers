// SPDX-License-Identifier: MIT

// SM3 (GB/T 32905-2016), 256-bit digest, plus HMAC-SM3 built on top of it.
// Dependency-free, like the BLAKE3 core next door.

#ifndef TSUBAKI_SM3_HASH_HPP
#define TSUBAKI_SM3_HASH_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sm3
{
inline constexpr std::size_t block_len = 64;
inline constexpr std::size_t digest_len = 32;
using digest_t = std::array<std::uint8_t, digest_len>;

inline std::uint32_t rotl(std::uint32_t x, unsigned n) noexcept
{
    n &= 31u;
    return n == 0 ? x : (x << n) | (x >> (32u - n));
}

inline std::uint32_t p0(std::uint32_t x) noexcept
{
    return x ^ rotl(x, 9) ^ rotl(x, 17);
}

inline std::uint32_t p1(std::uint32_t x) noexcept
{
    return x ^ rotl(x, 15) ^ rotl(x, 23);
}

class hasher
{
  private:
    std::uint32_t state_[8] = {0x7380166fu, 0x4914b2b9u, 0x172442d7u,
                               0xda8a0600u, 0xa96f30bcu, 0x163138aau,
                               0xe38dee4du, 0xb0fb0e4eu};
    std::array<std::uint8_t, block_len> buf_{};
    std::size_t buf_len_ = 0;
    std::uint64_t total_len_ = 0;

    void compress(const std::uint8_t *block) noexcept
    {
        std::uint32_t w[68];
        std::uint32_t w1[64];
        for (std::size_t i = 0; i < 16; ++i)
            w[i] = std::uint32_t(block[4 * i]) << 24 |
                   std::uint32_t(block[4 * i + 1]) << 16 |
                   std::uint32_t(block[4 * i + 2]) << 8 |
                   std::uint32_t(block[4 * i + 3]);
        for (std::size_t i = 16; i < 68; ++i)
            w[i] = p1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^
                   rotl(w[i - 13], 7) ^ w[i - 6];
        for (std::size_t i = 0; i < 64; ++i)
            w1[i] = w[i] ^ w[i + 4];

        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (std::size_t j = 0; j < 64; ++j)
        {
            const std::uint32_t tj = j < 16 ? 0x79cc4519u : 0x7a879d8au;
            const std::uint32_t ss1 =
                rotl(rotl(a, 12) + e + rotl(tj, static_cast<unsigned>(j)), 7);
            const std::uint32_t ss2 = ss1 ^ rotl(a, 12);
            const std::uint32_t ff =
                j < 16 ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
            const std::uint32_t gg =
                j < 16 ? (e ^ f ^ g) : ((e & f) | (~e & g));
            const std::uint32_t tt1 = ff + d + ss2 + w1[j];
            const std::uint32_t tt2 = gg + h + ss1 + w[j];
            d = c;
            c = rotl(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rotl(f, 19);
            f = e;
            e = p0(tt2);
        }

        state_[0] ^= a;
        state_[1] ^= b;
        state_[2] ^= c;
        state_[3] ^= d;
        state_[4] ^= e;
        state_[5] ^= f;
        state_[6] ^= g;
        state_[7] ^= h;
    }

  public:
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        if (input_len == 0)
            return;
        total_len_ += input_len;

        if (buf_len_ > 0)
        {
            const std::size_t take = std::min(block_len - buf_len_, input_len);
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
        const std::size_t tail_len = buf_len_ < block_len - 8 ? block_len : 2 * block_len;
        const std::uint64_t bit_len = total_len_ * 8;
        for (std::size_t i = 0; i < 8; ++i)
            tail[tail_len - 1 - i] = static_cast<std::uint8_t>(bit_len >> (8 * i));

        hasher copy = *this;
        copy.compress(tail.data());
        if (tail_len == 2 * block_len)
            copy.compress(tail.data() + block_len);

        digest_t digest{};
        for (std::size_t i = 0; i < 8; ++i)
            for (std::size_t b = 0; b < 4; ++b)
                digest[4 * i + b] =
                    static_cast<std::uint8_t>(copy.state_[i] >> (24 - 8 * b));
        return digest;
    }
};

namespace hmac
{
class hasher
{
  private:
    sm3::hasher inner_;
    std::array<std::uint8_t, sm3::block_len> opad_{};

  public:
    explicit hasher(const std::string &key) noexcept
    {
        std::array<std::uint8_t, sm3::block_len> k{};
        if (key.size() > sm3::block_len)
        {
            sm3::hasher kh;
            kh.update(reinterpret_cast<const std::uint8_t *>(key.data()),
                      key.size());
            const sm3::digest_t d = kh.finalize();
            std::copy(d.begin(), d.end(), k.begin());
        }
        else
        {
            std::copy(key.begin(), key.end(), k.begin());
        }

        std::array<std::uint8_t, sm3::block_len> ipad{};
        for (std::size_t i = 0; i < sm3::block_len; ++i)
        {
            ipad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36);
            opad_[i] = static_cast<std::uint8_t>(k[i] ^ 0x5c);
        }
        inner_.update(ipad.data(), ipad.size());
    }

    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        inner_.update(input, input_len);
    }

    sm3::digest_t finalize() const noexcept
    {
        const sm3::digest_t inner = inner_.finalize();
        sm3::hasher outer;
        outer.update(opad_.data(), opad_.size());
        outer.update(inner.data(), inner.size());
        return outer.finalize();
    }
};
} // namespace hmac
} // namespace sm3

#endif
