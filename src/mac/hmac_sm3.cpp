// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: HMAC-SM3 (keyed, 256-bit digest). Any non-empty key
// is accepted; HMAC hashes an over-long key instead of rejecting it.

#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"
#include "sm3_hash.hpp"

#include <expected>
#include <string>
#include <string_view>
#include <system_error>

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "hmac_sm3";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     32 bytes\n"
               "Key:        any length\n"
               "Note:       HMAC-SM3 (GB/T 32905-2016, RFC 2104). The Chinese standard hash\n"
               "            under HMAC.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const char *key,
                           std::size_t length) noexcept
    {
        return key != nullptr && length != 0;
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key,
                                                  std::size_t length) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        try
        {
            sm3::hmac::hasher hasher(std::string(key != nullptr ? key : "", length));
            provider_common::hash_file(hasher, path, out);
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
