# tsubaki-providers

Six algorithms for the dynamic provider ABI of
[tsubaki](https://github.com/Lawrence-Charland/Tsubaki-Next), built by one
CMake project. Each module is a standalone `.so` with no dependency beyond
libstdc++, so a provider directory holds the whole set.

为 [tsubaki](https://github.com/Lawrence-Charland/Tsubaki-Next) 的动态 provider
ABI 提供六个算法，全部由同一个 CMake 工程构建。每个模块都是独立的 `.so`，除
libstdc++ 外没有依赖，一个目录就能放下全套。

| Module | Algorithm | Digest | Keyed |
| --- | --- | --- | --- |
| `blake3.so` | BLAKE3 | 32 B | no |
| `sm3.so` | SM3 (GB/T 32905-2016) | 32 B | no |
| `hmac_sm3.so` | HMAC-SM3 | 32 B | **yes** |
| `sha512_256.so` | SHA-512/256 (FIPS 180-4) | 32 B | no |
| `sha3_224.so` | SHA3-224 (FIPS 202) | 28 B | no |
| `sha3_384.so` | SHA3-384 (FIPS 202) | 48 B | no |

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
tsubaki --algorithm                       # lists the six modules
tsubaki sum sm3 .                         # provider name, not a built-in
tsubaki sum hmac_sm3 . -k secret          # keyed provider
```

A built-in name always wins, so a provider cannot shadow one.

内建算法名优先，provider 覆盖不了它们。

Every module is compiled against
[`include/dynamic_provider_header.hpp`](./include/dynamic_provider_header.hpp),
a copy of tsubaki's contract: four `extern "C"` symbols, `noexcept` throughout,
lowercase hex of at least 32 characters, and the name is the contract.

每个模块都对着
[`include/dynamic_provider_header.hpp`](./include/dynamic_provider_header.hpp)
编译，那是 tsubaki 契约的副本：四个 `extern "C"` 符号、全程 `noexcept`、至少
32 个字符的小写十六进制，且名字本身就是契约。

A provider crosses the ABI with `std::string` / `std::filesystem::path` by
reference, so it needs the same compiler and standard library as the `tsubaki`
binary, built as C++23 on Linux.

provider 的 `std::string`、`std::filesystem::path` 是按引用跨 ABI 的，所以必须和
`tsubaki` 可执行文件用同一套编译器与标准库，在 Linux 上按 C++23 编译。

## License / 许可

GPL-2.0-only, see [COPYING](./COPYING).

GPL-2.0-only，见 [COPYING](./COPYING)。
