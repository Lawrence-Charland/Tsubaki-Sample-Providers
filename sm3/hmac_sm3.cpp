// SPDX-License-Identifier: GPL-2.0-only

// tsubaki dynamic provider: HMAC-SM3 (keyed, 256-bit digest). Any non-empty key
// is accepted; HMAC hashes an over-long key instead of rejecting it.

#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"
#include "sm3_hash.hpp"

#include <expected>
#include <filesystem>
#include <string>
#include <system_error>

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "hmac_sm3";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const std::string &key) noexcept
    {
        return !key.empty();
    }

    void tsubaki_checksum_file(
        const std::filesystem::path &path, const std::string &key,
        std::expected<std::string, std::error_code> &out) noexcept
    {
        try
        {
            sm3::hmac::hasher hasher(key);
            provider_common::hash_file(hasher, path, out);
        }
        catch (...)
        {
            out = provider_common::allocation_failure();
        }
    }
}
} // namespace tsubaki::provider
