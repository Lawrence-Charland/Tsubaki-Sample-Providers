// SPDX-License-Identifier: MIT

// tsubaki dynamic provider: SHA3-384 (FIPS 202), 48-byte digest. The rate is
// 832 bits, so 104 bytes are absorbed per permutation.

#include "dynamic_provider_header.hpp"
#include "keccak.hpp"
#include "provider_common.hpp"

#include <expected>
#include <filesystem>
#include <string>
#include <system_error>

namespace
{
using core = keccak::sponge<104, 48>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "sha3_384";
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
            provider_common::hash_file<core>(path, out);
        }
        catch (...)
        {
            out = provider_common::allocation_failure();
        }
    }
}
} // namespace tsubaki::provider
