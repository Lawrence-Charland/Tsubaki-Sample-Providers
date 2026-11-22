// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: KT128 (KangarooTwelve over TurboSHAKE128, RFC
// 9861), 32-byte digest, customization string fixed to empty.

#include "dynamic_provider_header.hpp"
#include "kangarootwelve.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
// TurboSHAKE128 leaves, 32-byte chaining values, 32-byte digest.
using core = provider_common::kangarootwelve<168, 32, 32>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "kt128";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     32 bytes\n"
               "Key:        none\n"
               "Note:       KT128, formerly KangarooTwelve (RFC 9861). Tree hashing over\n"
               "            TurboSHAKE128; the customization string is fixed to empty.";
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
