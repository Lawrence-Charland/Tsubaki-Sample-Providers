// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: KT256 (KangarooTwelve over TurboSHAKE256, RFC
// 9861), 64-byte digest, customization string fixed to empty.

#include "dynamic_provider_header.hpp"
#include "kangarootwelve.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
// TurboSHAKE256 leaves, 64-byte chaining values, 64-byte digest.
using core = provider_common::kangarootwelve<136, 64, 64>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "kt256";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     64 bytes\n"
               "Key:        none\n"
               "Note:       KT256 (RFC 9861). Tree hashing over TurboSHAKE256; the\n"
               "            customization string is fixed to empty.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return false;
    }

    bool tsubaki_check_key(const char *) noexcept
    {
        return true;
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *) noexcept
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
