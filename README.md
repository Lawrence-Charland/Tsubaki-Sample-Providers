# tsubaki-providers

Twenty-eight algorithms for the dynamic provider ABI of
[tsubaki](https://github.com/Lawrence-Charland/Tsubaki-Next), built by one
CMake project. Each module is a standalone `.so` with no dependency beyond
libstdc++, so a provider directory holds the whole set.

为 [tsubaki](https://github.com/Lawrence-Charland/Tsubaki-Next) 的动态 provider
ABI 提供二十八个算法，全部由同一个 CMake 工程构建。每个模块都是独立的 `.so`，除
libstdc++ 外没有依赖，一个目录就能放下全套。

| Module | Algorithm | Digest | Keyed |
| --- | --- | --- | --- |
| `aes_cmac.so` | AES-CMAC, 32/48/64 hex chars | 16 B | **yes** |
| `aria_cmac.so` | ARIA-CMAC (RFC 5794), 32/48/64 hex chars | 16 B | **yes** |
| `blake3.so` | BLAKE3 | 32 B | no |
| `blake3_keyed.so` | BLAKE3 keyed mode, 64 hex chars | 32 B | **yes** |
| `camellia_cmac.so` | Camellia-CMAC (RFC 3713), 32/48/64 hex chars | 16 B | **yes** |
| `hmac_sha512_224.so` | HMAC-SHA-512/224 | 28 B | **yes** |
| `hmac_sha512_256.so` | HMAC-SHA-512/256 | 32 B | **yes** |
| `hmac_sm3.so` | HMAC-SM3 | 32 B | **yes** |
| `keccak224.so` | Keccak-224 (Ethereum padding) | 28 B | no |
| `keccak256.so` | Keccak-256 (Ethereum padding) | 32 B | no |
| `keccak384.so` | Keccak-384 | 48 B | no |
| `keccak512.so` | Keccak-512 | 64 B | no |
| `kmac128.so` | KMAC128 (SP 800-185) | 32 B | **yes** |
| `kmac256.so` | KMAC256 (SP 800-185) | 64 B | **yes** |
| `kt128.so` | KT128 / KangarooTwelve (RFC 9861) | 32 B | no |
| `kt256.so` | KT256 / KangarooTwelve (RFC 9861) | 64 B | no |
| `ripemd160.so` | RIPEMD-160 (ISO/IEC 10118-3) | 20 B | no |
| `seed_cmac.so` | SEED-CMAC (RFC 4269), 32 hex chars | 16 B | **yes** |
| `sha3_224.so` | SHA3-224 (FIPS 202) | 28 B | no |
| `sha3_384.so` | SHA3-384 (FIPS 202) | 48 B | no |
| `sha512_224.so` | SHA-512/224 (FIPS 180-4) | 28 B | no |
| `sha512_256.so` | SHA-512/256 (FIPS 180-4) | 32 B | no |
| `shake128_256.so` | SHAKE128, fixed 32-byte output | 32 B | no |
| `shake256_512.so` | SHAKE256, fixed 64-byte output | 64 B | no |
| `sm3.so` | SM3 (GB/T 32905-2016) | 32 B | no |
| `sm4_cmac.so` | SM4-CMAC, 32 hex chars | 16 B | **yes** |
| `turboshake128_256.so` | TurboSHAKE128 (RFC 9861) | 32 B | no |
| `turboshake256_512.so` | TurboSHAKE256 (RFC 9861) | 64 B | no |

## Layout / 目录结构

```
src/hash/   unkeyed digests, one file per provider
src/mac/    keyed constructions: HMAC, CMAC, KMAC, keyed BLAKE3
include/    the ABI contract header and the shared hash/block-cipher cores
tests/      the vector checker and its expected-value tables
```

`src/hash/` 放无密钥摘要，`src/mac/` 放带密钥的 HMAC、CMAC、KMAC 与 keyed BLAKE3，
`include/` 放 ABI 契约头和公用的哈希/分组密码核心，`tests/` 放向量检查和它的期望值
表。源文件只用扁平 `#include`，也就是 `-Iinclude` 一挂就够，移动文件不用改包含路径。

## Build / 构建

Needs CMake 3.28 or newer with Ninja, and a C++23 compiler.

需要 CMake 3.28 或更新的版本（带 Ninja），以及支持 C++23 的编译器。

The presets mirror the main tsubaki repository: `linux-gcc-debug`,
`linux-gcc-release`, `linux-clang-debug` (a second compiler's opinion on
warnings), `macos-debug`/`macos-release`, `freebsd-debug`/`freebsd-release`,
and `posix-debug`/`posix-release` for the other POSIX systems. The Linux
presets pin their compiler by absolute path, so pass
`-DCMAKE_CXX_COMPILER=/path/to/c++` on the configure line if yours lives
elsewhere; the rest use the platform default.

预设与 tsubaki 主仓库一致：`linux-gcc-debug`、`linux-gcc-release`、
`linux-clang-debug`（换一个编译器核对告警）、`macos-debug`/`macos-release`、
`freebsd-debug`/`freebsd-release`，以及其它 POSIX 系统用的
`posix-debug`/`posix-release`。Linux 预设用绝对路径固定了编译器，装在别处就在配置时加
`-DCMAKE_CXX_COMPILER=/path/to/c++`；其余预设交给系统默认编译器。

```sh
cmake --preset linux-gcc-release
cmake --build --preset linux-gcc-release
ctest --test-dir build/linux-gcc-release --output-on-failure
```

The modules land in `build/linux-gcc-release`, next to a `check_vectors` binary
that hashes the test vectors twice: in one pass and in uneven pieces.

模块直接产出到 `build/linux-gcc-release`，同目录的 `check_vectors` 会把每组测试向量
按整块和碎块各算一遍。

## Use / 使用

```sh
export TSUBAKI_DYNAMIC_PROVIDER_PATHS=$PWD/build/linux-gcc-release
tsubaki --algorithm                       # lists the twenty-eight modules
tsubaki sum sm3 .                         # provider name, not a built-in
tsubaki sum hmac_sm3 . -k secret          # keyed provider
tsubaki sum kmac128 . -k secret           # SP 800-185 keyed provider
tsubaki sum sm4_cmac . -k 0123456789abcdeffedcba9876543210
tsubaki sum aes_cmac . -k 0123456789abcdeffedcba9876543210
tsubaki sum camellia_cmac . -k <32, 48 or 64 hex chars>
tsubaki sum blake3_keyed . -k <64 hex chars>
tsubaki algo-info aes_cmac                 # digest width, key format, notes
```

A built-in name always wins, so a provider cannot shadow one.

内建算法名优先，provider 覆盖不了它们。

Six providers take a binary key. The ABI hands the key over as a byte string
with an explicit length -- `tsubaki_check_key(key, length)` and
`tsubaki_checksum_file(path, key, length)` -- so a NUL inside a key is no longer
truncated. Each of them accepts either spelling: the hex text that can be
pasted onto a command line, or the raw bytes themselves, which is what `-K` is
for. `blake3_keyed` takes 32 bytes (64 hex characters), `sm4_cmac` and
`seed_cmac` take 16 bytes (32 characters), and `aes_cmac`, `camellia_cmac` and
`aria_cmac` take 16, 24 or 32 bytes (32, 48 or 64 characters). For the last
three, a 32-byte raw key made only of hex digits is read as a 16-byte hex key;
spell it out as 48 hex characters if that collision matters.

有六个 provider 的密钥是二进制。ABI 把密钥当字节串传，长度单独给出——
`tsubaki_check_key(key, length)`，以及对应的
`tsubaki_checksum_file(path, key, length)`——所以密钥里的 NUL 不再被截断。这六个
两种写法都收：能直接贴在命令行上的 hex 文本，或者原始字节（用 `-K` 指定文件）。
`blake3_keyed` 要 32 字节（64 个 hex 字符）；`sm4_cmac`、`seed_cmac` 要 16 字节
（32 个字符）；`aes_cmac`、`camellia_cmac`、`aria_cmac` 要 16、24 或 32 字节
（32、48 或 64 个字符）。后三个有个例外：如果 32 字节的原始密钥恰好全部是 hex
字符，它会被当成 16 字节的 hex 密钥；真在意的话就写成 48 个 hex 字符。
`kmac128`、`kmac256` 和几个 HMAC provider 则直接用密钥文本。

Every module is compiled against
[`include/dynamic_provider_header.hpp`](./include/dynamic_provider_header.hpp),
a copy of tsubaki's contract: four required `extern "C"` symbols plus an
optional `tsubaki_algo_info()`, `noexcept` throughout, lowercase hex of at least
32 characters, and the name is the contract. Every module here exports the
optional symbol, so `tsubaki algo-info` has something to print. The key is
passed with an explicit length, so a module built against the older two-argument
`tsubaki_check_key()` has to be rebuilt. The `Source:`
line in that output is tsubaki's own -- `built-in` or the module path -- and is
not part of what a module returns.

每个模块都对着
[`include/dynamic_provider_header.hpp`](./include/dynamic_provider_header.hpp)
编译，那是 tsubaki 契约的副本：四个必需的 `extern "C"` 符号，外加一个可选的
`tsubaki_algo_info()`，全程 `noexcept`、至少 32 个字符的小写十六进制，且名字本身
就是契约。本目录的模块全都导出了那个可选符号，所以 `tsubaki algo-info` 有东西可打。
密钥带长度传递，所以按旧的单参数 `tsubaki_check_key()` 编译的模块必须重编译。
输出里的 `Source:` 那一行是 tsubaki 自己加的——内建显示 `built-in`，动态模块显示
`.so` 路径——不属于模块返回的内容。

A provider crosses the ABI with plain data only: `const char *` arguments it may
read, and a `tsubaki_checksum_result` returned by value whose digest buffer
belongs to the caller. Nothing is allocated on one side and freed on the other,
so a `-fPIC` C++23 shared object for the same architecture is enough; it does
not have to share the host's standard library, but it must be self-contained
and match the host's glibc generation.

provider 跨 ABI 走的只有纯数据：只能读的 `const char *` 参数，以及一个按值返回、
摘要缓冲归调用方所有的 `tsubaki_checksum_result`。不会出现一边分配、另一边释放的
情况，所以只要是一个同架构的 `-fPIC` C++23 动态库就够了；它不必和宿主共用同一套
标准库，但必须自包含，并匹配宿主的 glibc 版本。

## Inner monologue / 内心 OS

The code here was written by DeepSeek against the Tsubaki DPF ABI; I
picked the algorithms, and checked every test vector and every bug at a block
boundary myself. Not much of a cryptographer, so slow and careful is the only
way I know. The repository exists to widen what Tsubaki can hash a little, and
to see how much this ABI can actually hold — more than I expected. More
algorithms that fit it will keep coming.

这个仓库的代码是“大肥鱼”（DeepSeek）照着 Tsubaki DPF 的 ABI 写的，算法是我挑的，
测试向量和边界上的坑也是我逐个核的，但本人实力确实不足以支持从头到尾实现所有算法。
写它的主要目的，是把 Tsubaki 的算法支持范围拓宽，看看这套 ABI 究竟能装下多少东西。
事实证明，能装的比想象中多。本仓库会持续更新更多适配这套 ABI 的算法，敬请关注！

## License / 许可

GPL-2.0-only, see [COPYING](./COPYING).

GPL-2.0-only，见 [COPYING](./COPYING)。
