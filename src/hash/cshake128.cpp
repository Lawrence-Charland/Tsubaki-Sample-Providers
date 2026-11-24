// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: cSHAKE128 (NIST SP 800-185) with a customization
// string. With --custom empty it is exactly SHAKE128 over the requested
// length, which is why the length is a parameter too: a XOF has no natural
// output size, and a manifest only records the algorithm name.
//
// The 32-byte default matches the standalone shake128_256 provider.

#include "cshake.hpp"
#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace
{
struct config
{
    std::size_t out_len = 32;
    std::vector<std::uint8_t> customization;
};

config settings;

constexpr const char *arg_script =
    "{\n"
    "    entry_name = custom;\n"
    "    entry_type = option;\n"
    "    long_name = custom;\n"
    "    max_value_count = 1;\n"
    "    explanations = customization string;\n"
    "}\n"
    "{\n"
    "    entry_name = length;\n"
    "    entry_type = option;\n"
    "    long_name = length;\n"
    "    max_value_count = 1;\n"
    "    explanations = output length in bytes, 1 to 128;\n"
    "}\n";

constexpr const char *usage_error =
    "cshake128: --custom takes a single string; --length takes a byte count "
    "from 1 to 128.";
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "cshake128";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     32 bytes by default, 1 to 128 with --length\n"
               "Key:        none\n"
               "Note:       cSHAKE128 (SP 800-185) with --custom as the customization string.\n"
               "            With --custom absent this is SHAKE128 at the same length.";
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
        if (args.count_at(0) > 1 || args.count_at(1) > 1)
            return usage_error;

        try
        {
            // The strings are tsubaki's and live only for this call, so the
            // customization string is copied before the hashing threads start.
            const std::string_view custom = args.at(0);
            settings.customization.assign(
                reinterpret_cast<const std::uint8_t *>(custom.data()),
                reinterpret_cast<const std::uint8_t *>(custom.data()) +
                    custom.size());

            const std::string_view length = args.at(1);
            if (!length.empty())
            {
                std::size_t parsed = 0;
                if (!provider_common::parse_size(length, 1, 128, parsed))
                    return usage_error;
                settings.out_len = parsed;
            }
        }
        catch (...)
        {
            return "cshake128: not enough memory to keep the customization "
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
            provider_common::cshake<168> hasher(settings.out_len, nullptr, 0,
                                               settings.customization.data(),
                                               settings.customization.size());
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
