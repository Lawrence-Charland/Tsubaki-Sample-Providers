// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// Hex decoding for the providers whose key is raw bytes, since the ABI only
// carries C strings.

#ifndef TSUBAKI_PROVIDER_HEX_KEY_HPP
#define TSUBAKI_PROVIDER_HEX_KEY_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace provider_common
{
inline int hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// True only when `key` is exactly 2 * out_len hex characters.
inline bool parse_hex(const char *key, std::uint8_t *out,
                      std::size_t out_len) noexcept
{
    if (key == nullptr || std::strlen(key) != 2 * out_len)
        return false;
    for (std::size_t i = 0; i < out_len; ++i)
    {
        const int hi = hex_value(key[2 * i]);
        const int lo = hex_value(key[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = static_cast<std::uint8_t>(hi << 4 | lo);
    }
    return true;
}
} // namespace provider_common

#endif
