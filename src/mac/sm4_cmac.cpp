// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: SM4-CMAC (keyed, 16-byte tag). The ABI key is a C
// string, so the 16-byte SM4 key travels as 32 hex characters.

#include "dynamic_provider_header.hpp"
#include "hex_key.hpp"
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
bool decode_key(const char *key, std::size_t length, std::uint8_t out[sm4::block_len]) noexcept
{
    return provider_common::decode_key_bytes(key, length, out, sm4::block_len);
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

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     16 bytes\n"
               "Key:        32 hex chars or 16 raw bytes\n"
               "Note:       SM4-CMAC (GB/T 32907-2016, SP 800-38B). The 16-byte key can be\n"
               "            given as 32 hex characters or as 16 raw bytes.\n"
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
        std::uint8_t decoded[sm4::block_len];
        return decode_key(key, length, decoded);
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key,
                                                  std::size_t length) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        std::uint8_t decoded[sm4::block_len];
        if (!decode_key(key, length, decoded))
        {
            out = std::unexpected(
                std::error_code(EINVAL, std::system_category()));
        }
        else
        {
            try
            {
                sm4::cmac hasher(decoded, sm4::block_len);
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
