// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: SM4-CMAC (keyed, 16-byte tag). The ABI key is a C
// string, so the 16-byte SM4 key travels as 32 hex characters.

#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"
#include "sm4.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <string>
#include <system_error>

namespace
{
int hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool decode_key(const char *key, std::uint8_t out[sm4::block_len]) noexcept
{
    if (key == nullptr || std::strlen(key) != 2 * sm4::block_len)
        return false;
    for (std::size_t i = 0; i < sm4::block_len; ++i)
    {
        const int hi = hex_value(key[2 * i]);
        const int lo = hex_value(key[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = static_cast<std::uint8_t>(hi << 4 | lo);
    }
    return true;
}
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "sm4_cmac";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const char *key) noexcept
    {
        std::uint8_t decoded[sm4::block_len];
        return decode_key(key, decoded);
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        std::uint8_t decoded[sm4::block_len];
        if (!decode_key(key, decoded))
        {
            out = std::unexpected(
                std::error_code(EINVAL, std::system_category()));
        }
        else
        {
            try
            {
                sm4::cmac hasher(decoded);
                provider_common::hash_file(hasher, path, out);
            }
            catch (...)
            {
                out = provider_common::allocation_failure();
            }
        }
        provider_common::deliver(out, result);
        return result;
    }
}
} // namespace tsubaki::provider
