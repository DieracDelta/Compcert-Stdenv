# Hardening CompCert

What gcc/clang offer as hardening, what upstream CompCert does about each, what
others have built, and what the patches in `patches/` add.

These patches only make changes that come with a proof. Everything they change
in the compiler is covered by CompCert's semantic-preservation theorem; the code
that prints and expands assembly is trusted, as it is upstream. That theorem
still only speaks about programs without undefined behaviour. The canary check,
for example, is proved never to fail on such programs; nothing proves that
canaries stop an attack.

## Summary

| Feature (gcc/clang flag) | Upstream CompCert | Prior work | These patches |
|---|---|---|---|
| Stack canaries (`-fstack-protector[-strong\|-all]`) | no | Chamois-CompCert, verified (Monniaux, CPP 2024) | **ported with its proof**: x86-64, IA32, AArch64 |
| AArch64 return-address signing (`-mbranch-protection=pac-ret`) | no | Chamois `-fretaddr-pac`, verified (CPP 2024) | not ported (larger change to Mach, Stacking and the AArch64 back end) |
| CET IBT/SHSTK (`-fcf-protection`), AArch64 BTI (`-mbranch-protection=bti`) | no; [AbsInt#556](https://github.com/AbsInt/CompCert/issues/556) | Chamois `-fbranch-target-protection`, unverified (assembly printing) | no |
| Stack clash protection (`-fstack-clash-protection`) | no | none found | no |
| Register zeroing (`-fzero-call-used-regs`) | no | none for CompCert; Jasmin has verified zeroization (CCS 2024 "High-assurance zeroization") | no |
| `-ftrivial-auto-var-init` | no | none found | no |
| `_FORTIFY_SOURCE` | no | none found | no |
| `-Wformat -Werror=format-security` | no printf format checking | none found | no |
| `-fno-strict-overflow` / `-fwrapv` | already: signed arithmetic wraps in CompCert's semantics | — | — |
| `-fno-strict-aliasing` | already: no type-based alias analysis | — | — |
| PIE / PIC | yes on x86-64 and AArch64 Linux | — | — |
| RELRO, BIND_NOW, non-executable stack | linker side; `.note.GNU-stack` emitted | — | — |
| Spectre (retpolines, `-mharden-sls`, speculative load hardening) | no | constant-time CompCert (Barthe et al., POPL 2020); fence insertion in CompCert (PriSC 2026); SpecIBT (Rocq, not CompCert) | no |
| Forward-edge CFI (`-fsanitize=cfi`, kCFI) | no | none found | no |
| `-fharden-compares`, `-fharden-conditional-branches` | no | none found | no |
| `-fstrict-flex-arrays`, `_GLIBCXX_ASSERTIONS`, libc++ hardening | not applicable (no object-size checks; C only) | — | — |

Unverified implementations of CET/BTI landing pads, stack-clash probing and
register zeroing were written and tested, then left out because they have no
proof.

## Stack canaries — `-fstack-protector`, `-fstack-protector-strong`, `-fstack-protector-all`

`backend/Canary.v` and `backend/Canaryproof.v` come from
[Chamois-CompCert](https://gricad-gitlab.univ-grenoble-alpes.fr/certicompil/Chamois-CompCert)
(David Monniaux, "Memory simulations, security and optimization in a verified
compiler", CPP 2024, [arXiv 2312.08117](https://arxiv.org/abs/2312.08117)),
taken from the September 2023 state, before Chamois changed its memory model.

The pass works on RTL after dead-code elimination. Functions with
stack-allocated variables (every function with `-all`) get an aligned slot past
their variables. The canary is stored there on entry and compared before every
return and tail call; a mismatch calls `__stack_chk_fail`. `-strong` means the
same as `-fstack-protector`, since "has stack-allocated variables" in CompCert
is close to gcc's `-strong` criterion.

Changes needed against upstream:
- RTL has no trapping mode on `Iload` and no prediction field on `Icond`;
  internal calls have an argument-typing premise.
- `Mem.loadv`/`Mem.storev` now refuse accesses that cross the end of the
  address space. `canary_needed` therefore bounds `canary_offset +
  canary_size`, not just the offset, and the proof shows that the canary
  load and store pass the check.
- Rocq 9.2 no longer has the `Zmod` notation.

New assumptions: the canary values (`Values.canary32_val`,
`Values.canary64_val`) and the two option flags. Targets: x86-64 and IA32
(canary at `%fs:40` / `%gs:20`), AArch64 (`__stack_chk_guard`); Linux only.
ARM, PowerPC and RISC-V set `getcanary := None`, which turns the pass into the
identity. Reading the canary and calling `__stack_chk_fail` are printed by the
trusted assembly printer, like every other instruction.

Known weakness, from the paper: gcc clears the register that held the canary;
CompCert's register allocator deletes that clearing.

## Upstream bugs fixed on the way

- **AArch64 prologues could leave SP misaligned.** The frame layout aligned the
  back link to 8 only, so for frames whose upper part exceeds 512 bytes the
  prologue stored the back link and return address through an SP that was
  8 mod 16. Linux checks SP alignment, so this raised SIGBUS. It showed up in
  SQLite (`sqlite3RunParser`) in Signal's SQLCipher addon and is present in
  3.18. Fixed in the verified frame layout (`aarch64/Stacklayout.v`, lemma
  `frame_env_link_aligned`), not in the unverified expansion.
- **Linux headers on AArch64 need 128-bit integer types.** Even
  `#define _GNU_SOURCE` followed by `#include <signal.h>` did not compile.
  `configure` now undefines `__SIZEOF_INT128__`, as on x86-64, and maps
  `__u128`/`__uint128_t` to a 16-byte, 16-aligned structure, which gives gcc's
  layout. This is preprocessor configuration, outside what CompCert proves.

## Testing

- Proofs build for x86-64, AArch64, IA32, RISC-V 64, ARM and PowerPC.
- `nix build .#compcert-hardened-tests` runs CompCert's test suite
  (AbsInt/CompCert-small-tests, 154 tests) with `-fstack-protector-all`.
- `nix build .#compcert-hardening-check` compiles a test program through
  nixpkgs' cc-wrapper with its default hardening and checks that an overflow
  aborts with "stack smashing detected".
- Both pass on x86_64-linux and aarch64-linux, natively.
