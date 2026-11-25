// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: CRC-64/XZ (ECMA-182 polynomial, reflected), the
// checksum xz and lzma store per block. 8 bytes of output, 16 hex characters.

#include "crc.hpp"
#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
using core = provider_common::crc64_xz;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "crc64";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     8 bytes\n"
               "Key:        none\n"
               "Note:       CRC-64/XZ (ECMA-182 polynomial, reflected), the checksum the xz\n"
               "            container uses. Not a cryptographic digest.\n"
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
            provider_common::hash_file<core>(path, out);
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
