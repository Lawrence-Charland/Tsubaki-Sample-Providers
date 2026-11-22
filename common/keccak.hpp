// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// Keccak-f[1600] and the sponge, parameterised by rate, digest size and domain
// byte, so every member of the family shares one core.

#ifndef TSUBAKI_KECCAK_HPP
#define TSUBAKI_KECCAK_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace keccak
{
inline std::uint64_t rotl(std::uint64_t x, unsigned n) noexcept
{
    return n == 0 ? x : (x << n) | (x >> (64u - n));
}

// rounds is 24 for Keccak-f[1600] proper, or 12 for Keccak-p[1600,12], which
// FIPS 202 defines as the last 12 rounds of the full permutation.
template <unsigned rounds = 24> inline void f1600(std::uint64_t a[25]) noexcept
{
    static_assert(rounds == 12 || rounds == 24,
                  "Keccak-p[1600] is only used with 12 or 24 rounds");
    static constexpr std::uint64_t round_constant[24] = {
        0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull,
        0x8000000080008000ull, 0x000000000000808bull, 0x0000000080000001ull,
        0x8000000080008081ull, 0x8000000000008009ull, 0x000000000000008aull,
        0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
        0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull,
        0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull,
        0x000000000000800aull, 0x800000008000000aull, 0x8000000080008081ull,
        0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull};
    // Rotation offsets, indexed x + 5y.
    static constexpr unsigned rho[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55,
                                         20, 3,  10, 43, 25, 39, 41, 45, 15,
                                         21, 8,  18, 2,  61, 56, 14};

    for (std::size_t round = 0; round < rounds; ++round)
    {
        std::uint64_t c[5];
        for (std::size_t x = 0; x < 5; ++x)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (std::size_t x = 0; x < 5; ++x)
        {
            const std::uint64_t d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
            for (std::size_t y = 0; y < 5; ++y)
                a[x + 5 * y] ^= d;
        }

        std::uint64_t b[25];
        for (std::size_t y = 0; y < 5; ++y)
            for (std::size_t x = 0; x < 5; ++x)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], rho[x + 5 * y]);

        for (std::size_t y = 0; y < 5; ++y)
            for (std::size_t x = 0; x < 5; ++x)
                a[x + 5 * y] = b[x + 5 * y] ^
                               (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);

        a[0] ^= round_constant[round + (24 - rounds)];
    }
}

// rate is the sponge rate in bytes (144 for SHA3-224, 104 for SHA3-384, 136
// for Keccak-256). domain is the byte that integrates the first padding bit:
// 0x06 for SHA-3, 0x01 for plain Keccak, 0x1F for SHAKE and TurboSHAKE.
// rounds selects the permutation: 24 for everything FIPS 202 defines, 12 for
// the reduced variant that TurboSHAKE and KangarooTwelve build on.
template <std::size_t rate, std::size_t out_len, std::uint8_t domain = 0x06,
          unsigned rounds = 24>
class sponge
{
    static_assert(rate % 8 == 0 && rate < 200, "rate is a whole number of lanes");
    static_assert(out_len <= rate, "one squeeze pass is enough");

  private:
    std::uint64_t state_[25] = {};
    std::array<std::uint8_t, rate> buf_{};
    std::size_t buf_len_ = 0;

    void absorb(const std::uint8_t *block) noexcept
    {
        for (std::size_t lane = 0; lane < rate / 8; ++lane)
        {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < 8; ++i)
                value |= std::uint64_t(block[8 * lane + i]) << (8 * i);
            state_[lane] ^= value;
        }
        f1600<rounds>(state_);
    }

  public:
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        if (input_len == 0)
            return;

        if (buf_len_ > 0)
        {
            const std::size_t take = std::min(rate - buf_len_, input_len);
            std::copy(input, input + take, buf_.begin() + buf_len_);
            buf_len_ += take;
            input += take;
            input_len -= take;
            if (buf_len_ == rate)
            {
                absorb(buf_.data());
                buf_len_ = 0;
            }
        }
        while (input_len >= rate)
        {
            absorb(input);
            input += rate;
            input_len -= rate;
        }
        if (input_len > 0)
        {
            std::copy(input, input + input_len, buf_.begin());
            buf_len_ = input_len;
        }
    }

    std::array<std::uint8_t, out_len> finalize() const noexcept
    {
        sponge copy = *this;
        // The domain byte carries the first padding bit, 0x80 sets the last.
        copy.buf_[copy.buf_len_] = domain;
        for (std::size_t i = copy.buf_len_ + 1; i < rate; ++i)
            copy.buf_[i] = 0;
        copy.buf_[rate - 1] ^= 0x80;
        copy.absorb(copy.buf_.data());

        std::array<std::uint8_t, out_len> digest{};
        for (std::size_t i = 0; i < out_len; ++i)
            digest[i] =
                static_cast<std::uint8_t>(copy.state_[i / 8] >> (8 * (i % 8)));
        return digest;
    }
};
} // namespace keccak

#endif
