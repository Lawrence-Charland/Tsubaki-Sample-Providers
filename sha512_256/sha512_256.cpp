// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: SHA-512/256 (FIPS 180-4), 32-byte digest.

#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"
#include "sha512_hash.hpp"

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
        return "sha512_256";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return false;
    }

    bool tsubaki_check_key(const std::string &) noexcept
    {
        return true;
    }

    void tsubaki_checksum_file(
        const std::filesystem::path &path, const std::string &,
        std::expected<std::string, std::error_code> &out) noexcept
    {
        try
        {
            provider_common::hash_file<sha512_256::hasher>(path, out);
        }
        catch (...)
        {
            out = provider_common::allocation_failure();
        }
    }
}
} // namespace tsubaki::provider
