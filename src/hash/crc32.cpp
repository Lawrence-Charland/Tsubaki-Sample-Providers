// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: CRC-32, the reflected IEEE 802.3 polynomial that
// zlib, PKZIP and Ethernet all use. 32-bit output, 8 hex characters: a
// checksum, meant to catch transfer damage rather than tampering.

#include "crc.hpp"
#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
using core = provider_common::crc32_ieee;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "crc32";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     4 bytes\n"
               "Key:        none\n"
               "Note:       CRC-32 (IEEE 802.3, poly 0x04C11DB7 reflected), the zlib,\n"
               "            PKZIP and Ethernet checksum. Not a cryptographic digest.";
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
