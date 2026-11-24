// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: BLAKE2b (RFC 7693) with its parameter block
// exposed. The digest length, a 16-byte salt and a 16-byte personalization
// string are arguments rather than separate algorithm names, because with the
// defaults they hash exactly what the built-in blake2b512 does.
//
// The 64-byte default is therefore the familiar BLAKE2b-512: a manifest
// written without --length reads back under the name `blake2b`, not
// `blake2b512`, and the two names are different contracts.

#include "blake2.hpp"
#include "dynamic_provider_header.hpp"
#include "hex_key.hpp"
#include "provider_common.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>

namespace
{
struct config
{
    std::size_t out_len = 64;
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> personal{};
};

// take_args() runs once, on the main thread, before any file is hashed. The
// checksum callback then reads this from several worker threads at once, so
// nothing here is written after take_args() returns.
config settings;

constexpr const char *arg_script =
    "{\n"
    "    entry_name = length;\n"
    "    entry_type = option;\n"
    "    long_name = length;\n"
    "    max_value_count = 1;\n"
    "    explanations = digest length in bytes, 1 to 64;\n"
    "}\n"
    "{\n"
    "    entry_name = salt;\n"
    "    entry_type = option;\n"
    "    long_name = salt;\n"
    "    max_value_count = 1;\n"
    "    explanations = 16-byte salt as 32 hex characters;\n"
    "}\n"
    "{\n"
    "    entry_name = personal;\n"
    "    entry_type = option;\n"
    "    long_name = personal;\n"
    "    max_value_count = 1;\n"
    "    explanations = 16-byte personalization string as 32 hex characters;\n"
    "}\n";

constexpr const char *usage_error =
    "blake2b: --length takes a byte count from 1 to 64; --salt and --personal "
    "take exactly 32 hex characters (16 bytes).";
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "blake2b";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     64 bytes by default, 1 to 64 with --length\n"
               "Key:        none (use blake2b512_mac for the keyed mode)\n"
               "Note:       BLAKE2b (RFC 7693) with salt and personalization as parameters.\n"
               "            With the defaults this is BLAKE2b-512; --length 32 gives\n"
               "            BLAKE2b-256, which is a different digest, not a truncation.";
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
        if (args.count_at(0) > 1 || args.count_at(1) > 1 || args.count_at(2) > 1)
            return usage_error;

        const std::string_view length = args.at(0);
        if (!length.empty())
        {
            std::size_t parsed = 0;
            if (!provider_common::parse_size(length, 1, 64, parsed))
                return usage_error;
            settings.out_len = parsed;
        }


        const std::string_view salt = args.at(1);
        if (!salt.empty() &&
            !provider_common::parse_hex(salt.data(), salt.size(),
                                        settings.salt.data(),
                                        settings.salt.size()))
            return usage_error;

        const std::string_view personal = args.at(2);
        if (!personal.empty() &&
            !provider_common::parse_hex(personal.data(), personal.size(),
                                        settings.personal.data(),
                                        settings.personal.size()))
            return usage_error;

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
            provider_common::blake2b hasher(settings.out_len, settings.salt,
                                            settings.personal);
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
