// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: KT256 (KangarooTwelve over TurboSHAKE256, RFC
// 9861), 64-byte digest, with --custom as the customization string.

#include "dynamic_provider_header.hpp"
#include "kangarootwelve.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace
{
// TurboSHAKE256 leaves, 64-byte chaining values, 64-byte digest.
using core = provider_common::kangarootwelve<136, 64, 64>;

std::vector<std::uint8_t> customization;

constexpr const char *arg_script =
    "{ entry_name = custom; entry_type = option; long_name = custom; "
    "max_value_count = 1; explanations = customization string; }\n";
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
               "Note:       KT256 (RFC 9861). Tree hashing over TurboSHAKE256. Use --custom for\n"
               "            the customization string; without it the string is empty.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return false;
    }

    bool tsubaki_check_key(const char *, std::size_t) noexcept
    {
        return true;
    }

    bool tsubaki_need_more_args() noexcept
    {
        return true;
    }

    const char *tsubaki_arg_definition() noexcept
    {
        return arg_script;
    }

    const char *tsubaki_take_args(tsubaki_pass_content *content,
                                  std::size_t cnt) noexcept
    {
        const provider_common::passed_args args{content, cnt};
        if (args.count_at(0) > 1)
            return "kt256: --custom takes a single string.";
        try
        {
            const std::string_view custom = args.at(0);
            customization.assign(
                reinterpret_cast<const std::uint8_t *>(custom.data()),
                reinterpret_cast<const std::uint8_t *>(custom.data()) +
                    custom.size());
        }
        catch (...)
        {
            return "kt256: not enough memory to keep the customization "
                   "string.";
        }
        return "";
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *,
                                                  std::size_t) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        try
        {
            core hasher(customization);
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
