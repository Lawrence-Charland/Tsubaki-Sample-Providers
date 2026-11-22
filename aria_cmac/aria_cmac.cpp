// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: ARIA-CMAC (keyed, 16-byte tag, RFC 5794). The ABI
// key is a C string, so the ARIA key travels as hex: 32, 48 or 64 characters
// for 128, 192 or 256 bits.

#include "aria.hpp"
#include "cmac.hpp"
#include "dynamic_provider_header.hpp"
#include "hex_key.hpp"
#include "provider_common.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <string>
#include <system_error>

namespace
{
using core = provider_common::cmac<aria::cipher>;

bool decode_key(const char *key, std::uint8_t *out,
                std::size_t &out_len) noexcept
{
    if (key == nullptr)
        return false;
    const std::size_t chars = std::strlen(key);
    if (chars != 32 && chars != 48 && chars != 64)
        return false;
    out_len = chars / 2;
    return provider_common::parse_hex(key, out, out_len);
}
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "aria_cmac";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     16 bytes\n"
               "Key:        32, 48 or 64 hex chars\n"
               "Note:       ARIA-CMAC (RFC 5794, SP 800-38B). The key arrives as hex: 32, 48\n"
               "            or 64 characters for 128-, 192- or 256-bit ARIA.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const char *key) noexcept
    {
        std::uint8_t decoded[32];
        std::size_t len = 0;
        return decode_key(key, decoded, len);
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        std::uint8_t decoded[32];
        std::size_t len = 0;
        if (!decode_key(key, decoded, len))
        {
            out = std::unexpected(
                std::error_code(EINVAL, std::system_category()));
        }
        else
        {
            try
            {
                core hasher(decoded, len);
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
