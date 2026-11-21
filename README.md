# tsubaki-providers

Eighteen algorithms for the dynamic provider ABI of
[tsubaki](https://github.com/Lawrence-Charland/Tsubaki-Next), built by one
CMake project. Each module is a standalone `.so` with no dependency beyond
libstdc++, so a provider directory holds the whole set.

为 [tsubaki](https://github.com/Lawrence-Charland/Tsubaki-Next) 的动态 provider
ABI 提供十八个算法，全部由同一个 CMake 工程构建。每个模块都是独立的 `.so`，除
libstdc++ 外没有依赖，一个目录就能放下全套。

| Module | Algorithm | Digest | Keyed |
| --- | --- | --- | --- |
| `blake3.so` | BLAKE3 | 32 B | no |
| `blake3_keyed.so` | BLAKE3 keyed mode, 64 hex chars | 32 B | **yes** |
| `hmac_sha512_224.so` | HMAC-SHA-512/224 | 28 B | **yes** |
| `hmac_sha512_256.so` | HMAC-SHA-512/256 | 32 B | **yes** |
| `hmac_sm3.so` | HMAC-SM3 | 32 B | **yes** |
| `keccak256.so` | Keccak-256 (Ethereum padding) | 32 B | no |
| `keccak512.so` | Keccak-512 | 64 B | no |
| `kmac128.so` | KMAC128 (SP 800-185) | 32 B | **yes** |
| `kmac256.so` | KMAC256 (SP 800-185) | 64 B | **yes** |
| `ripemd160.so` | RIPEMD-160 (ISO/IEC 10118-3) | 20 B | no |
| `sha3_224.so` | SHA3-224 (FIPS 202) | 28 B | no |
| `sha3_384.so` | SHA3-384 (FIPS 202) | 48 B | no |
| `sha512_224.so` | SHA-512/224 (FIPS 180-4) | 28 B | no |
| `sha512_256.so` | SHA-512/256 (FIPS 180-4) | 32 B | no |
| `shake128_256.so` | SHAKE128, fixed 32-byte output | 32 B | no |
| `shake256_512.so` | SHAKE256, fixed 64-byte output | 64 B | no |
| `sm3.so` | SM3 (GB/T 32905-2016) | 32 B | no |
| `sm4_cmac.so` | SM4-CMAC, 32 hex chars | 16 B | **yes** |

## Build / 构建

Needs CMake 3.28 or newer with Ninja, and a C++23 compiler.

需要 CMake 3.28 或更新的版本（带 Ninja），以及支持 C++23 的编译器。

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
tsubaki --algorithm                       # lists the eighteen modules
tsubaki sum sm3 .                         # provider name, not a built-in
tsubaki sum hmac_sm3 . -k secret          # keyed provider
tsubaki sum kmac128 . -k secret           # SP 800-185 keyed provider
tsubaki sum sm4_cmac . -k 0123456789abcdeffedcba9876543210
tsubaki sum blake3_keyed . -k <64 hex chars>
```

A built-in name always wins, so a provider cannot shadow one.

内建算法名优先，provider 覆盖不了它们。

Two providers need a binary key, which the ABI's C string cannot carry
verbatim: `blake3_keyed` takes 32 bytes as 64 hex characters and `sm4_cmac`
takes 16 bytes as 32 hex characters. `kmac128`, `kmac256` and the HMAC
providers use the key text as-is.

有两个 provider 的密钥是二进制，C 字符串带不了原样字节：`blake3_keyed` 要 32 字节，
按 64 个 hex 字符传；`sm4_cmac` 要 16 字节，按 32 个 hex 字符传。`kmac128`、
`kmac256` 和几个 HMAC provider 则直接用密钥文本。

Every module is compiled against
[`include/dynamic_provider_header.hpp`](./include/dynamic_provider_header.hpp),
a copy of tsubaki's contract: four `extern "C"` symbols, `noexcept` throughout,
lowercase hex of at least 32 characters, and the name is the contract.

每个模块都对着
[`include/dynamic_provider_header.hpp`](./include/dynamic_provider_header.hpp)
编译，那是 tsubaki 契约的副本：四个 `extern "C"` 符号、全程 `noexcept`、至少
32 个字符的小写十六进制，且名字本身就是契约。

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

## License / 许可

GPL-2.0-only, see [COPYING](./COPYING).

GPL-2.0-only，见 [COPYING](./COPYING)。
