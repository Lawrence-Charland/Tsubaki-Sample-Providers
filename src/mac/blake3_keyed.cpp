// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: BLAKE3 keyed mode (32-byte digest). The ABI key is
// a C string, so the 32-byte key travels as 64 hex characters.

#include "blake3_hash.hpp"
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
bool decode_key(const char *key, std::size_t length,
                std::uint8_t out[32]) noexcept
{
    return provider_common::decode_key_bytes(key, length, out, 32);
}
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "blake3_keyed";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     32 bytes\n"
               "Key:        64 hex chars or 32 raw bytes\n"
               "Note:       BLAKE3 keyed mode. The 32-byte key is the first four words of the\n"
               "            key schedule; pass it as 64 hex characters or as 32 raw bytes.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const char *key,
                           std::size_t length) noexcept
    {
        std::uint8_t decoded[32];
        return decode_key(key, length, decoded);
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key,
                                                  std::size_t length) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        std::uint8_t decoded[32];
        if (!decode_key(key, length, decoded))
        {
            out = std::unexpected(
                std::error_code(EINVAL, std::system_category()));
        }
        else
        {
            try
            {
                b3::hasher hasher(decoded);
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
