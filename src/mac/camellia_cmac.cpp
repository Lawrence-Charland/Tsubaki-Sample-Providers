// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: Camellia-CMAC (keyed, 16-byte tag, RFC 3713). The ABI
// key is a C string, so the Camellia key travels as hex: 32, 48 or 64 characters
// for 128, 192 or 256 bits.

#include "camellia.hpp"
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
using core = provider_common::cmac<camellia::cipher>;

bool decode_key(const char *key, std::size_t length, std::uint8_t *out,
                std::size_t &out_len) noexcept
{
    return provider_common::decode_key_variable(key, length, out, out_len);
}
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "camellia_cmac";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     16 bytes\n"
               "Key:        32/48/64 hex or 16/24/32 raw bytes\n"
               "Note:       Camellia-CMAC (RFC 3713, SP 800-38B). The key may be 32, 48 or 64\n"
               "            hex characters, or 16, 24 or 32 raw bytes.\n"
               "            Part of tsubaki-providers:\n"
               "            https://github.com/Lawrence-Charland/Tsubaki-Sample-Providers.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const char *key,
                           std::size_t length) noexcept
    {
        std::uint8_t decoded[32];
        std::size_t len = 0;
        return decode_key(key, length, decoded, len);
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key,
                                                  std::size_t length) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        std::uint8_t decoded[32];
        std::size_t len = 0;
        if (!decode_key(key, length, decoded, len))
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
