// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: RIPEMD-160 (ISO/IEC 10118-3), 20-byte digest.

#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"
#include "ripemd160.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "ripemd160";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     20 bytes\n"
               "Key:        none\n"
               "Note:       RIPEMD-160 (ISO/IEC 10118-3). A 160-bit hash from the EU RIPE\n"
               "            project, still used by Bitcoin.\n"
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
            provider_common::hash_file<ripemd160::hasher>(path, out);
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
