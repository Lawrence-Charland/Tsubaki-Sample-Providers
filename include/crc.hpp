// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// The reflected table-driven CRC, the shape every widely used file CRC takes:
// CRC-32 (zlib, PKZIP), CRC-32C (Castagnoli, ext4 and iSCSI) and CRC-64/XZ
// all differ only in width and polynomial. A CRC is a checksum, not a digest:
// its whole value fits in four or eight bytes and it detects transfer damage,
// not tampering.

#ifndef TSUBAKI_PROVIDER_CRC_HPP
#define TSUBAKI_PROVIDER_CRC_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace provider_common
{
// CRCs are defined over a polynomial with the top bit implicit, so the
// constant here is the reversed form of the normal one: CRC-32's 0x04C11DB7
// is 0xEDB88320 once reflected for the right-to-left variant.
template <typename T, T ReflectedPoly> class reflected_crc
{
  private:
    static const std::array<T, 256> &table() noexcept
    {
        static const std::array<T, 256> built = []
        {
            std::array<T, 256> t{};
            for (std::size_t i = 0; i < 256; ++i)
            {
                T value = static_cast<T>(i);
                for (unsigned bit = 0; bit < 8; ++bit)
                    value = (value & 1) ? (value >> 1) ^ ReflectedPoly
                                        : value >> 1;
                t[i] = value;
            }
            return t;
        }();
        return built;
    }

    T state_ = static_cast<T>(~T{0});

  public:
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        const auto &t = table();
        for (std::size_t i = 0; i < input_len; ++i)
            state_ = t[(state_ ^ input[i]) & 0xff] ^ (state_ >> 8);
    }

    // The value is written big-endian, the way every CRC is spelled in
    // listings: zlib's 0x352441c2 for "abc" reads back as 352441c2.
    std::array<std::uint8_t, sizeof(T)> finalize() const noexcept
    {
        const T value = static_cast<T>(~state_);
        std::array<std::uint8_t, sizeof(T)> out{};
        for (std::size_t i = 0; i < sizeof(T); ++i)
            out[i] = static_cast<std::uint8_t>(value >> (8 * (sizeof(T) - 1 - i)));
        return out;
    }
};

using crc32_ieee = reflected_crc<std::uint32_t, 0xEDB88320u>;
using crc32_castagnoli = reflected_crc<std::uint32_t, 0x82F63B78u>;
using crc64_xz = reflected_crc<std::uint64_t, 0xC96C5795D7870F42ull>;
} // namespace provider_common

#endif
