// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: SHA-512/256 (FIPS 180-4), 32-byte digest.

#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"
#include "sha512_hash.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "sha512_256";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     32 bytes\n"
               "Key:        none\n"
               "Note:       SHA-512/256 (FIPS 180-4). SHA-512 truncated to 256 bits, with its\n"
               "            own initial value.\n"
               "            Part of tsubaki-providers:\n"
               "            https://github.com/Lawrence-Charland/Tsubaki-Sample-Providers.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return false;
    }

    bool tsubaki_check_key(const char *, std::size_t) noexcept
    {
        return true;
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *,
                                                  std::size_t) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        try
        {
            provider_common::hash_file<sha512_256::hasher>(path, out);
        }
        catch (...)
        {
            out = provider_common::allocation_failure();
        }
        provider_common::deliver(out, result);
        return result;
    }
}
} // namespace tsubaki::provider
