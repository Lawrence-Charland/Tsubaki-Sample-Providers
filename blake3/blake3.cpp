// SPDX-License-Identifier: MIT

// tsubaki dynamic provider: BLAKE3 (unkeyed, 32-byte digest).

#include "blake3_hash.hpp"
#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"

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
        return "blake3";
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
            provider_common::hash_file<b3::hasher>(path, out);
        }
        catch (...)
        {
            out = provider_common::allocation_failure();
        }
    }
}
} // namespace tsubaki::provider
