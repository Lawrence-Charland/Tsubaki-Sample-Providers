// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// Camellia (RFC 3713, ISO/IEC 18033-3): 128-bit block, 128/192/256-bit key,
// 18 or 24 rounds. Forward direction only, since CMAC never decrypts.
//
// SBOX2..4 are byte rotations of SBOX1, so only one table is carried.

#ifndef TSUBAKI_PROVIDER_CAMELLIA_HPP
#define TSUBAKI_PROVIDER_CAMELLIA_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace camellia
{
inline constexpr std::size_t block_len = 16;
using block_t = std::array<std::uint8_t, block_len>;

inline constexpr std::uint8_t sbox1[256] = {
    0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35,
    0xea, 0x0c, 0xae, 0x41, 0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21,
    0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd, 0x86, 0xb8, 0xaf, 0x8f,
    0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6,
    0x51, 0x56, 0x6c, 0x4d, 0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d,
    0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99, 0xdf, 0x4c, 0xcb, 0xc2,
    0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16,
    0x53, 0x18, 0xf2, 0x22, 0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91,
    0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50, 0xaa, 0xd0, 0xa0, 0x7d,
    0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda,
    0x09, 0x3f, 0xdd, 0x94, 0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33,
    0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2, 0x52, 0x9b, 0xd8, 0x26,
    0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6,
    0x2f, 0xfd, 0xb4, 0x59, 0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba,
    0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa, 0x72, 0x07, 0xb9, 0x55,
    0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4,
    0x77, 0xc7, 0x80, 0x9e};

inline std::uint8_t rotl8(std::uint8_t v, unsigned n) noexcept
{
    return static_cast<std::uint8_t>((v << n) | (v >> (8 - n)));
}

inline std::uint32_t rotl32(std::uint32_t v, unsigned n) noexcept
{
    return (v << n) | (v >> (32 - n));
}

inline std::uint8_t sbox2(std::uint8_t x) noexcept
{
    return rotl8(sbox1[x], 1);
}

inline std::uint8_t sbox3(std::uint8_t x) noexcept
{
    return rotl8(sbox1[x], 7);
}

inline std::uint8_t sbox4(std::uint8_t x) noexcept
{
    return sbox1[rotl8(x, 1)];
}

inline std::uint64_t be64(const std::uint8_t *p) noexcept
{
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

inline void put_be64(std::uint8_t *p, std::uint64_t v) noexcept
{
    for (std::size_t i = 0; i < 8; ++i)
        p[7 - i] = static_cast<std::uint8_t>(v >> (8 * i));
}

// F-function, RFC 3713 section 2.4.1.
inline std::uint64_t f(std::uint64_t in, std::uint64_t ke) noexcept
{
    const std::uint64_t x = in ^ ke;
    const std::uint8_t t1 = sbox1[(x >> 56) & 0xff];
    const std::uint8_t t2 = sbox2(static_cast<std::uint8_t>((x >> 48) & 0xff));
    const std::uint8_t t3 = sbox3(static_cast<std::uint8_t>((x >> 40) & 0xff));
    const std::uint8_t t4 = sbox4(static_cast<std::uint8_t>((x >> 32) & 0xff));
    const std::uint8_t t5 = sbox2(static_cast<std::uint8_t>((x >> 24) & 0xff));
    const std::uint8_t t6 = sbox3(static_cast<std::uint8_t>((x >> 16) & 0xff));
    const std::uint8_t t7 = sbox4(static_cast<std::uint8_t>((x >> 8) & 0xff));
    const std::uint8_t t8 = sbox1[x & 0xff];

    const std::uint8_t y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    const std::uint8_t y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    const std::uint8_t y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    const std::uint8_t y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    const std::uint8_t y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    const std::uint8_t y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    const std::uint8_t y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    const std::uint8_t y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

    return static_cast<std::uint64_t>(y1) << 56 |
           static_cast<std::uint64_t>(y2) << 48 |
           static_cast<std::uint64_t>(y3) << 40 |
           static_cast<std::uint64_t>(y4) << 32 |
           static_cast<std::uint64_t>(y5) << 24 |
           static_cast<std::uint64_t>(y6) << 16 |
           static_cast<std::uint64_t>(y7) << 8 | y8;
}

inline std::uint64_t fl(std::uint64_t in, std::uint64_t ke) noexcept
{
    std::uint32_t x1 = static_cast<std::uint32_t>(in >> 32);
    std::uint32_t x2 = static_cast<std::uint32_t>(in);
    const std::uint32_t k1 = static_cast<std::uint32_t>(ke >> 32);
    const std::uint32_t k2 = static_cast<std::uint32_t>(ke);
    x2 ^= rotl32(x1 & k1, 1);
    x1 ^= x2 | k2;
    return static_cast<std::uint64_t>(x1) << 32 | x2;
}

inline std::uint64_t flinv(std::uint64_t in, std::uint64_t ke) noexcept
{
    std::uint32_t y1 = static_cast<std::uint32_t>(in >> 32);
    std::uint32_t y2 = static_cast<std::uint32_t>(in);
    const std::uint32_t k1 = static_cast<std::uint32_t>(ke >> 32);
    const std::uint32_t k2 = static_cast<std::uint32_t>(ke);
    y1 ^= y2 | k2;
    y2 ^= rotl32(y1 & k1, 1);
    return static_cast<std::uint64_t>(y1) << 32 | y2;
}

struct u128
{
    std::uint64_t hi;
    std::uint64_t lo;
};

inline u128 rol128(u128 x, unsigned n) noexcept
{
    n %= 128;
    if (n == 0)
        return x;
    if (n == 64)
        return {x.lo, x.hi};
    if (n < 64)
        return {(x.hi << n) | (x.lo >> (64 - n)),
                (x.lo << n) | (x.hi >> (64 - n))};
    n -= 64;
    return {(x.lo << n) | (x.hi >> (64 - n)),
            (x.hi << n) | (x.lo >> (64 - n))};
}

inline constexpr std::uint64_t sigma1 = 0xA09E667F3BCC908Bull;
inline constexpr std::uint64_t sigma2 = 0xB67AE8584CAA73B2ull;
inline constexpr std::uint64_t sigma3 = 0xC6EF372FE94F82BEull;
inline constexpr std::uint64_t sigma4 = 0x54FF53A5F1D36F1Cull;
inline constexpr std::uint64_t sigma5 = 0x10E527FADE682D1Dull;
inline constexpr std::uint64_t sigma6 = 0xB05688C2B3E6C1FDull;

inline u128 make_ka(u128 kl, u128 kr) noexcept
{
    std::uint64_t d1 = kl.hi ^ kr.hi;
    std::uint64_t d2 = kl.lo ^ kr.lo;
    d2 ^= f(d1, sigma1);
    d1 ^= f(d2, sigma2);
    d1 ^= kl.hi;
    d2 ^= kl.lo;
    d2 ^= f(d1, sigma3);
    d1 ^= f(d2, sigma4);
    return {d1, d2};
}

inline u128 make_kb(u128 ka, u128 kr) noexcept
{
    std::uint64_t d1 = ka.hi ^ kr.hi;
    std::uint64_t d2 = ka.lo ^ kr.lo;
    d2 ^= f(d1, sigma5);
    d1 ^= f(d2, sigma6);
    return {d1, d2};
}

class cipher
{
  public:
    using block_t = ::camellia::block_t;
    static constexpr std::size_t block_len = ::camellia::block_len;

  private:
    std::uint64_t kw_[4] = {};
    std::uint64_t k_[24] = {};
    std::uint64_t ke_[6] = {};
    std::size_t groups_ = 0;

  public:
    cipher(const std::uint8_t *key, std::size_t key_len) noexcept
    {
        const u128 kl{be64(key), be64(key + 8)};
        u128 kr{0, 0};
        if (key_len == 24)
        {
            // The rightmost 64 bits and their complement.
            const std::uint64_t right = be64(key + 16);
            kr = {right, ~right};
        }
        else if (key_len == 32)
        {
            kr = {be64(key + 16), be64(key + 24)};
        }

        const u128 ka = make_ka(kl, kr);

        if (key_len == 16)
        {
            groups_ = 3;
            kw_[0] = rol128(kl, 0).hi;
            kw_[1] = rol128(kl, 0).lo;
            k_[0] = rol128(ka, 0).hi;
            k_[1] = rol128(ka, 0).lo;
            k_[2] = rol128(kl, 15).hi;
            k_[3] = rol128(kl, 15).lo;
            k_[4] = rol128(ka, 15).hi;
            k_[5] = rol128(ka, 15).lo;
            ke_[0] = rol128(ka, 30).hi;
            ke_[1] = rol128(ka, 30).lo;
            k_[6] = rol128(kl, 45).hi;
            k_[7] = rol128(kl, 45).lo;
            k_[8] = rol128(ka, 45).hi;
            // RFC 3713's table really does take k10 from KL <<< 60, not from
            // the lower half of KA <<< 45; the two halves interleave.
            k_[9] = rol128(kl, 60).lo;
            k_[10] = rol128(ka, 60).hi;
            k_[11] = rol128(ka, 60).lo;
            ke_[2] = rol128(kl, 77).hi;
            ke_[3] = rol128(kl, 77).lo;
            k_[12] = rol128(kl, 94).hi;
            k_[13] = rol128(kl, 94).lo;
            k_[14] = rol128(ka, 94).hi;
            k_[15] = rol128(ka, 94).lo;
            k_[16] = rol128(kl, 111).hi;
            k_[17] = rol128(kl, 111).lo;
            kw_[2] = rol128(ka, 111).hi;
            kw_[3] = rol128(ka, 111).lo;
            return;
        }

        groups_ = 4;
        const u128 kb = make_kb(ka, kr);
        kw_[0] = rol128(kl, 0).hi;
        kw_[1] = rol128(kl, 0).lo;
        k_[0] = rol128(kb, 0).hi;
        k_[1] = rol128(kb, 0).lo;
        k_[2] = rol128(kr, 15).hi;
        k_[3] = rol128(kr, 15).lo;
        k_[4] = rol128(ka, 15).hi;
        k_[5] = rol128(ka, 15).lo;
        ke_[0] = rol128(kr, 30).hi;
        ke_[1] = rol128(kr, 30).lo;
        k_[6] = rol128(kb, 30).hi;
        k_[7] = rol128(kb, 30).lo;
        k_[8] = rol128(kl, 45).hi;
        k_[9] = rol128(kl, 45).lo;
        k_[10] = rol128(ka, 45).hi;
        k_[11] = rol128(ka, 45).lo;
        ke_[2] = rol128(kl, 60).hi;
        ke_[3] = rol128(kl, 60).lo;
        k_[12] = rol128(kr, 60).hi;
        k_[13] = rol128(kr, 60).lo;
        k_[14] = rol128(kb, 60).hi;
        k_[15] = rol128(kb, 60).lo;
        k_[16] = rol128(kl, 77).hi;
        k_[17] = rol128(kl, 77).lo;
        ke_[4] = rol128(ka, 77).hi;
        ke_[5] = rol128(ka, 77).lo;
        k_[18] = rol128(kr, 94).hi;
        k_[19] = rol128(kr, 94).lo;
        k_[20] = rol128(ka, 94).hi;
        k_[21] = rol128(ka, 94).lo;
        k_[22] = rol128(kl, 111).hi;
        k_[23] = rol128(kl, 111).lo;
        kw_[2] = rol128(kb, 111).hi;
        kw_[3] = rol128(kb, 111).lo;
    }

    block_t encrypt(const block_t &in) const noexcept
    {
        std::uint64_t d1 = be64(in.data()) ^ kw_[0];
        std::uint64_t d2 = be64(in.data() + 8) ^ kw_[1];

        for (std::size_t g = 0; g < groups_; ++g)
        {
            for (std::size_t j = 0; j < 6; ++j)
            {
                const std::size_t r = 6 * g + j;
                if (r % 2 == 0)
                    d2 ^= f(d1, k_[r]);
                else
                    d1 ^= f(d2, k_[r]);
            }
            if (g + 1 < groups_)
            {
                d1 = fl(d1, ke_[2 * g]);
                d2 = flinv(d2, ke_[2 * g + 1]);
            }
        }

        d2 ^= kw_[2];
        d1 ^= kw_[3];

        block_t out{};
        put_be64(out.data(), d2);
        put_be64(out.data() + 8, d1);
        return out;
    }
};
} // namespace camellia

#endif
