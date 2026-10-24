# binscope test corpus

121 small, **benign** binaries built from the C sources in `src/` by `build.sh`.
They exist so every binscope test runs against real ELF, PE and Mach-O files
whose provenance is fully known. Nothing here was downloaded.

| family      | what the program does                                               |
|-------------|----------------------------------------------------------------------|
| `hello`     | prints a greeting (PE builds also carry a UTF-16 banner)            |
| `files`     | writes a temp file, reads it back, deletes it                       |
| `net`       | sends one TCP "ping" to 127.0.0.1 (loopback only)                   |
| `plainblob` | CRC-32 of a 24 KiB generated-text blob in a dedicated section       |
| `packed`    | same program, blob stored zlib-compressed (high-entropy section)    |

Each family has 4 variants (`-v0`..`-v3`: different strings / constants) built
for 6 targets: `elf-x86_64`, `elf-aarch64`, `pe-x86_64`, `pe-i686`,
`macho-arm64`, `macho-x86_64`, plus one universal Mach-O (`macho-universal/hello-v0`).

* Linux builds are freestanding (`crt0` in `src/stubs`) and link against a
  stub `libc.so.6` so they carry real dynamic imports; at run time they would
  bind to the system C library.
* Windows builds are freestanding and link against import libraries generated
  from the `.def` files in `src/stubs`. `ws2_32` functions are deliberately
  imported **by ordinal** to exercise imphash's ordinal mapping.
* There is no unpacking stub in `packed`: it is an entropy contrast, not a
  packer.

`MANIFEST.tsv` lists sha256, size, target, family and variant for every file.
Rebuild with `fixtures/build.sh` (needs clang, rust-lld from the Rust
toolchain, lipo and python3). Rebuilding on the same toolchain is
byte-for-byte deterministic; a different clang/lld version will produce
different bytes, after which `tests/reference/*.tsv` must be regenerated
(`scripts/reference/`).
