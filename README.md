# compcert-stdenv

[CompCert](https://compcert.org), the formally verified C compiler, as a
nixpkgs stdenv, with stack canaries that come with a proof, and packages built
with it. Linux on x86_64 and aarch64.

## Use

As an overlay in another flake (it only adds attributes):

```nix
inputs.compcert-stdenv.url = "git+https://forgejo.desktop.restivo.me/jrestivo/compcert-stdenv.git";
inputs.compcert-stdenv.inputs.nixpkgs.follows = "nixpkgs";
# ...
nixpkgs.overlays = [ inputs.compcert-stdenv.overlays.default ];
# then: pkgs.compcertStdenv, pkgs.signal-desktop-compcert, ...
```

CompCert is unfree (INRIA non-commercial license), so the package set needs
`allowUnfree` or a predicate that admits `compcert`. This flake's own outputs
set one.

Directly: `nix build .#hello-compcert`, `nix build .#signal-desktop-compcert`,
`nix develop` (a shell whose `$CC` is CompCert).

| Attribute | What |
|---|---|
| `compcert-hardened` | `ccomp` from AbsInt master (`2685140b`) plus `patches/` |
| `compcertCC`, `compcertStdenv` | `ccomp` behind a flag-translating shim, as a stdenv C compiler |
| `hello-compcert` | Smoke test; fails if the object came from gcc |
| `compcert-hardening-check` | nixpkgs' stack-protector flag reaches ccomp; an overflow aborts |
| `compcert-hardened-tests` | CompCert's own test suite with `-fstack-protector-all` |
| `sqlcipher-compcert` | SQLCipher 4.20 (OpenSSL provider) compiled by ccomp |
| `signal-desktop-compcert` | Signal Desktop whose `@signalapp/sqlcipher` addon has its C (the `sqlite3.c` amalgamation) compiled by ccomp |

In Signal, SQLCipher is the only C component: libsignal is Rust, BoringSSL is
C++, and RingRTC/WebRTC and Electron are C++.

## Patches

Only changes that come with a proof, or are not something CompCert proves
anything about. [HARDENING.md](HARDENING.md) has the inventory of gcc/clang
hardening, CompCert's status for each, prior work, and details.

| Patch | What | Proof |
|---|---|---|
| 0001 | `-fstack-protector[-strong\|-all]`: Chamois-CompCert's canary pass and proof (Monniaux, CPP 2024), ported to upstream (x86-64, IA32, AArch64) | verified; proofs build on x86-64, AArch64, IA32, RISC-V, ARM, PowerPC |
| 0002 | configure: 128-bit integer types in Linux headers on AArch64/RISC-V. Upstream bug: on aarch64, `#define _GNU_SOURCE` + `#include <signal.h>` did not compile | preprocessor configuration, outside what CompCert proves |
| 0003 | AArch64: 16-align the back link in the frame layout. Upstream bug, present in 3.18: frames over 512 bytes stored through an SP that was 8 mod 16, which is SIGBUS on Linux; it crashed SQLite inside Signal's addon | verified: `Stacklayout.v`, lemma `frame_env_link_aligned` |

The shim passes nixpkgs' stack-protector flags to ccomp and declares the other
compiler-level hardening flags (fortify, shadowstack, stackclashprotection,
zerocallusedregs, pacret, format, …) unsupported. `strictoverflow` is already
CompCert's semantics (signed arithmetic wraps). PIE, RELRO and BIND_NOW work as
with gcc.

## How the shim works

`ccomp` compiles C to assembly and hands preprocessing, assembling and linking
to the normal gcc wrapper. It also fails on any option it doesn't recognise.
The shim:

- translates `-std=gnu*` and `-O*`, and drops gcc-only `-f*`/`-m*`/`--param`
  flags;
- clears cc-wrapper's "flags already added" variables, so the inner gcc adds
  crt1.o and the libc paths itself. It keeps only the linker hardening (RELRO,
  BIND_NOW) for that inner gcc;
- undefines `__has_c_attribute`, `__has_builtin`, `__has_extension` and
  `__has_feature`. gcc's preprocessor advertises them, and headers then emit
  `[[attrs]]`, `typeof` or `__atomic_*` code that ccomp can't compile or link;
- sets `_DEFAULT_SOURCE` and turns implicit function declarations into errors,
  maps glibc's C2y `_Countof`, and passes `-fstruct-passing` so struct
  arguments and returns follow gcc's ABI.

## SQLCipher and Signal

- `void*` arithmetic in `sqlcipher_mlock`/`munlock` gets a `char*` cast.
- SQLCipher 4.20 only: `__thread` on the xoshiro state becomes a plain static.
  CompCert has no TLS. That PRNG is only used for wiping memory and tests, not
  for keys, but the change **is a data race**.
- Signal's addon: `SQLITE_USE_ALLOCA` is removed, since CompCert has no
  `alloca`. With `__GNUC__` undefined, glibc declares `alloca` as an ordinary
  function, so this would otherwise fail only when the library is loaded.
- `-D_GNU_SOURCE -flongdouble`, plus `libcompcert.a` linked explicitly when g++
  does the final link.
- Stock nixpkgs `signal-desktop` doesn't ship its from-source
  `signal-sqlcipher`: it replaces the `node_modules/@signalapp/sqlcipher`
  symlink, but electron-builder packages pnpm dependencies from
  `node_modules/.pnpm`, so the npm prebuilt `.node` ends up in the app. This
  overlay also replaces the copy in `.pnpm` and `cmp`s the packaged addon
  against the ccomp build.

## Caveats

- CompCert's correctness theorem only covers programs without undefined
  behaviour, so on its own it doesn't stop exploitation of memory-safety bugs.
  The canary proof shows the check never fires on UB-free programs; nothing
  proves canaries stop attacks.
- No CET/BTI, stack-clash protection, register zeroing, `_FORTIFY_SOURCE` or
  `-Wformat-security` for CompCert-compiled code.
- Signal Desktop built this way hasn't been launched against a real profile.

## License

CompCert and the patches to it are under the
[INRIA non-commercial license](https://compcert.org/doc/LICENSE.txt). The
canary pass comes from
[Chamois-CompCert](https://gricad-gitlab.univ-grenoble-alpes.fr/certicompil/Chamois-CompCert),
under the same license.
