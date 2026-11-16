# CompCert (the formally verified C compiler) as a stdenv, plus the packages
# that have been made to build with it.
#
# Adds new attributes only; nothing existing is replaced.
#   compcert-hardened         ccomp with the patches in ./patches
#   compcert-hardened-tests   CompCert's own test suite with -fstack-protector-all
#   compcertCC                C compiler wrapper (ccomp behind a gcc-flag shim)
#   compcertStdenv            stdenv whose C compiler is ccomp
#   hello-compcert            smoke test: builds, runs, checks it wasn't gcc
#   sqlcipher-compcert        SQLCipher with the OpenSSL provider
#   signal-desktop-compcert   Signal Desktop with its SQLCipher addon built by ccomp
#   compcert-hardening-check  checks nixpkgs' stack-protector flag reaches ccomp
#
# CompCert's correctness theorem only covers programs without undefined
# behaviour, so it does not mitigate memory-safety bugs by itself. Upstream
# ccomp has no hardening. The patches only add what comes with a proof:
#   -fstack-protector[-strong|-all]  stack canaries (pass and proof from
#                                    Chamois-CompCert, Monniaux CPP 2024)
# plus two aarch64 fixes (16-aligned back link in the verified frame layout;
# 128-bit types in Linux headers, in configure). CET/BTI, stack-clash probing,
# register zeroing, _FORTIFY_SOURCE etc. stay off. PIE, NX stack, RELRO and
# BIND_NOW work as with gcc.
#
# Linux on x86_64 and aarch64 (both CompCert targets; both tested).
final: prev:
let
  inherit (prev) lib stdenv;
  compcert = final.compcert-hardened;

  # ccomp does C -> assembly itself and runs `cc` (the normal gcc wrapper, set
  # as its toolprefix in nixpkgs) to preprocess, assemble and link.
  #
  # ccomp rejects unknown options, so translate or drop gcc-only flags that
  # cc-wrapper, hardening and ordinary build systems pass.
  shim = prev.writeShellScript "gcc" ''
    # Introspection queries go straight to gcc; ccomp has no equivalent.
    for a in "$@"; do
      case "$a" in
        -print-*|-dumpmachine|-dumpversion|-dumpfullversion|-dumpspecs)
          exec ${stdenv.cc}/bin/cc "$@" ;;
      esac
    done

    args=()
    while [ $# -gt 0 ]; do
      a="$1"; shift
      case "$a" in
        # ccomp knows c99/c11/c18 only
        -std=c89|-std=c90|-std=gnu89|-std=gnu90|-ansi|-std=iso9899:1990) args+=(-std=c99) ;;
        -std=gnu99|-std=c99|-std=iso9899:1999) args+=(-std=c99) ;;
        -std=gnu11|-std=c11|-std=gnu1x|-std=c1x) args+=(-std=c11) ;;
        -std=gnu17|-std=gnu18|-std=c17|-std=c18|-std=gnu2x|-std=c2x|-std=gnu23|-std=c23) args+=(-std=c18) ;;

        -Og|-Ofast|-Oz) args+=(-O) ;;

        # -f flags ccomp understands
        -fpic|-fPIC|-fpie|-fPIE|-fno-pic|-fno-PIC|-fno-pie|-fno-PIE) args+=("$a") ;;
        -fall|-fnone|-fbitfields|-fdiagnostics-color|-fno-diagnostics-color) args+=("$a") ;;
        -f*common|-f*longdouble|-f*struct-passing|-f*vararg-calls|-f*unprototyped) args+=("$a") ;;
        -f*unstructured-switch|-f*packed-structs|-f*inline-asm|-f*tailcalls) args+=("$a") ;;
        -f*if-conversion|-f*const-prop|-f*cse|-f*redundancy|-f*inline) args+=("$a") ;;
        -f*inline-functions-called-once|-f*fpu|-f*sse|-fmax-errors=*) args+=("$a") ;;
        # stack canaries: the verified pass in the patched ccomp
        -fstack-protector|-fstack-protector-strong|-fstack-protector-all|-fno-stack-protector) args+=("$a") ;;
        # every other -f (fortify, -frandom-seed, prefix maps, visibility, lto, ...) is dropped
        -f*) ;;

        # machine flags and gcc-internal search paths
        -m*|-B|-B*) [ "$a" = -B ] && shift ;;
        --param) shift ;;
        --param=*) ;;

        -pipe|-pthread|-pthreads) ;;
        -rdynamic) args+=(-Wl,-export-dynamic) ;;
        -g*) case "$a" in -g|-g0|-g1|-g2|-g3|-gdwarf-2|-gdwarf-3) args+=("$a") ;; *) args+=(-g) ;; esac ;;

        *) args+=("$a") ;;
      esac
    done

    # The outer cc-wrapper marks its flags as added; reset that so the inner gcc
    # ccomp spawns adds crt1.o, glibc include paths etc. itself. Keep only the
    # linker-level hardening (RELRO, BIND_NOW): the compiler flags were already
    # passed to ccomp, and the inner gcc would otherwise fortify the headers
    # ccomp parses.
    keep=""
    for f in ''${NIX_HARDENING_ENABLE-}; do
      case "$f" in relro|bindnow) keep="$keep $f" ;; esac
    done
    for v in ''${!NIX_CC_WRAPPER_FLAGS_SET_*} ''${!NIX_BINTOOLS_WRAPPER_FLAGS_SET_*} ''${!NIX_HARDENING_ENABLE_*}; do unset "$v"; done
    export NIX_HARDENING_ENABLE="$keep"

    # ccomp preprocesses with gcc, whose cpp advertises gcc features; headers
    # then emit code ccomp can't parse or link:
    #   __has_c_attribute              -> C23 [[attributes]] (gnulib)
    #   __has_builtin                  -> __builtin_*_overflow + typeof (gnulib)
    #   __has_extension/__has_feature  -> __atomic_* calls (SQLite)
    # ccomp always preprocesses in strict -std=c99 mode; gcc's default is gnu17,
    # i.e. _DEFAULT_SOURCE, so restore that header visibility. Implicit function
    # declarations are errors, as in gcc >= 14: an implicitly-declared
    # localtime_r returns a truncated int, not a pointer.
    # glibc's <stdcountof.h> expands countof() to the C2y keyword _Countof,
    # which ccomp lacks; on arrays (its only valid operands) this is the same.
    # -fstruct-passing makes struct arguments/returns ABI-compatible with gcc.
    exec ${compcert}/bin/ccomp -U_FORTIFY_SOURCE \
      -U__has_c_attribute -U__has_builtin -U__has_extension -U__has_feature \
      -Wp,-Wno-builtin-macro-redefined \
      -fstruct-passing -funstructured-switch -finline-asm \
      -D_DEFAULT_SOURCE -Werror=implicit-function-declaration \
      '-D_Countof(a)=(sizeof(a) / sizeof((a)[0]))' \
      "''${args[@]}"
  '';

  shimPackage =
    prev.runCommand "compcert-gcc-shim-${compcert.version}"
      {
        inherit (compcert) version;
        # Supported: stackprotector (verified canary pass), pic, and relro and
        # bindnow (linker). strictoverflow is already CompCert's semantics
        # (signed arithmetic wraps). The rest would need unverified code.
        passthru.hardeningUnsupportedFlags = [
          "fortify"
          "fortify3"
          "shadowstack"
          "stackclashprotection"
          "zerocallusedregs"
          "nostrictaliasing"
          "pacret"
          "strictflexarrays1"
          "strictflexarrays3"
          "strictoverflow"
          "libcxxhardeningfast"
          "libcxxhardeningextensive"
          "glibcxxassertions"
          "format"
          "trivialautovarinit"
        ];
      }
      ''
        mkdir -p $out/bin
        ln -s ${shim} $out/bin/gcc
      '';

  # ccomp-generated code calls helpers (__compcert_i64_dtou, ...) from this
  # archive. ccomp adds it when it links; when g++ or another linker does, add
  # it by hand.
  compcertRuntime = "${compcert}/lib/compcert/libcompcert.a";

  hardeningC = prev.writeText "hardening.c" ''
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    int n;
    int victim(const char *src) { char buf[16]; memcpy(buf, src, n); return buf[0]; }
    int big(int i) { char b[20000]; memset(b, i, sizeof b); return b[i]; }
    int main(int argc, char **argv) {
      char src[64]; memset(src, 'A', sizeof src);
      n = atoi(argv[1]);
      printf("%d %d\n", victim(src), big(3));
      return 0;
    }
  '';

  helloC = prev.writeText "hello.c" ''
    #include <stdio.h>
    int main(void) { printf("hello from CompCert\n"); return 0; }
  '';

  # Fail the build if an object didn't come from ccomp: gcc always writes a
  # "GCC: (GNU) ..." .comment section, ccomp never does.
  assertCompcertObject = obj: ''
    test -f ${obj}
    if ${stdenv.cc.bintools.bintools}/bin/readelf -p .comment ${obj} 2>/dev/null | grep -q GCC; then
      echo "${obj} was compiled by gcc, not ccomp" >&2
      exit 1
    fi
  '';
in
lib.optionalAttrs
  (lib.elem prev.stdenv.hostPlatform.system [
    "x86_64-linux"
    "aarch64-linux"
  ])
  {
    # AbsInt master after 3.18 plus ./patches (see HARDENING.md).
    compcert-hardened = prev.compcert.overrideAttrs {
      version = "3.18-unstable-2026-11-16-hardened";
      src = prev.fetchFromGitHub {
        owner = "AbsInt";
        repo = "CompCert";
        rev = "2685140bf72c959446981fb99b5e44a8975021bc";
        hash = "sha256-VTc+w2pdwwfHt7SEhQwbmmtqL0V5wdmNNGNoOG04+ys=";
      };
      patches = [
        ./patches/0001-Stack-protector-verified-fstack-protector-strong-all.patch
        ./patches/0002-configure-128-bit-integer-types-in-Linux-headers-on-.patch
        ./patches/0003-AArch64-16-align-the-back-link-in-the-frame-layout.patch
      ];
    };

    # CompCert's own test suite (AbsInt/CompCert-small-tests) against the
    # hardened ccomp, with canaries in every function.  A separate derivation
    # so that the compiler itself does not depend on the tests.
    compcert-hardened-tests = final.compcert-hardened.overrideAttrs {
      name = "compcert-hardened-tests";
      postBuild = ''
        cp -r ${
          prev.fetchFromGitHub {
            owner = "AbsInt";
            repo = "CompCert-small-tests";
            rev = "71c682d6b3a74e1a7d5da30285b5735761031da3";
            hash = "sha256-c9zEFkvEzyZbS+uJoN5HO7gBThXvAzSCZEGj074OTeI=";
          }
        }/. test/
        chmod -R u+w test
        make -C test CCOMPOPTS="-fstack-protector-all" all
        make -C test test 2>&1 | tee test.log
        ! grep -i "fail\|wrong" test.log | grep -v "failed as expected"
      '';
      installPhase = "mkdir -p $out && cp test.log $out/";
      outputs = [ "out" ];
    };

    compcertCC = prev.wrapCCWith {
      cc = shimPackage;
      inherit (stdenv.cc) bintools libc;
    };

    compcertStdenv = prev.overrideCC stdenv final.compcertCC;

    # nixpkgs' default stack-protector flag reaches ccomp and the verified
    # canary pass takes effect: an overflow aborts.
    compcert-hardening-check = final.compcertStdenv.mkDerivation {
      name = "compcert-hardening-check";
      dontUnpack = true;
      buildPhase = ''
        $CC -O2 -S -o h.s ${hardeningC}
        $CC -O2 -o h ${hardeningC}
        ./h 8
        set +e; ./h 40 2> err; rc=$?; set -e
        echo "overflow: rc=$rc $(cat err)"
        grep -q "stack smashing detected" err
        grep -q ${if stdenv.hostPlatform.isx86 then "'%fs:40'" else "__stack_chk_guard"} h.s
      '';
      installPhase = "touch $out";
    };

    hello-compcert = final.compcertStdenv.mkDerivation {
      name = "hello-compcert";
      dontUnpack = true;
      buildPhase = ''
        $CC -O2 -c -o hello.o ${helloC}
        ${assertCompcertObject "hello.o"}
        $CC -o hello hello.o
      '';
      installPhase = ''
        install -Dm755 hello $out/bin/hello
      '';
      doInstallCheck = true;
      installCheckPhase = ''
        $out/bin/hello
      '';
    };

    # SQLCipher (SQLite + encryption codec) with the OpenSSL crypto provider.
    # OpenSSL itself stays gcc-built; SQLCipher's own C goes through ccomp.
    sqlcipher-compcert =
      (prev.sqlcipher.override { stdenv = final.compcertStdenv; }).overrideAttrs
        (old: {
          pname = "sqlcipher-compcert";
          # Non-CompCert-C in SQLCipher's own code:
          #  - GNU arithmetic on void* in sqlcipher_mlock/munlock -> cast to char*.
          #  - __thread state for the xoshiro PRNG (CompCert has no TLS). That PRNG
          #    is only for anti-forensic memory spray and tests, not key material;
          #    here it becomes a plain static, which is racy across threads.
          postPatch = (old.postPatch or "") + ''
            substituteInPlace src/sqlcipher.c \
              --replace-fail 'ptr - offset' '(char *)ptr - offset' \
              --replace-quiet 'static __thread volatile uint64_t xoshiro_s[4];' 'static volatile uint64_t xoshiro_s[4];'
          '';
          # SQLite defines _GNU_SOURCE only `#if defined(__GNUC__)`, which ccomp
          # isn't. Without __GNUC__, glibc's isnan()/isinf() dispatch on
          # sizeof(long double), and ccomp rejects that type unless -flongdouble
          # (long double == double; ABI-incompatible if actually passed to glibc,
          # but SQLite only uses it internally). CFLAGS rather than
          # NIX_CFLAGS_COMPILE, which also reaches the build-platform gcc.
          env = old.env // {
            CFLAGS = "-O2 -g -D_GNU_SOURCE -flongdouble";
          };
          # depsBuildBuild puts a plain gcc earlier on PATH; pin CC or the build
          # silently uses gcc.
          preConfigure = (old.preConfigure or "") + ''
            export CC=${final.compcertCC}/bin/cc
          '';
          postBuild = (old.postBuild or "") + assertCompcertObject "sqlite3.o";
        });

    signal-desktop-compcert =
      let
        orig = prev.signal-desktop.signal-sqlcipher;

        # Signal's @signalapp/sqlcipher addon, exactly as Signal Desktop pins it.
        # It mixes C (sqlite3.c), C++ (N-API glue) and Rust (crypto provider, FTS
        # tokenizer), so the stdenv stays gcc and only the C compiler is ccomp.
        signal-sqlcipher = orig.overrideAttrs (old: {
          pname = "node-sqlcipher-compcert";
          postPatch = (old.postPatch or "") + ''
            # CompCert has no alloca. Without __GNUC__, glibc declares alloca as
            # an ordinary extern, so this only fails at dlopen time. SQLite falls
            # back to heap allocation.
            substituteInPlace deps/sqlcipher/sqlcipher.gyp \
              --replace-quiet "'SQLITE_USE_ALLOCA'," ""
            substituteInPlace deps/sqlcipher/sqlite3.c \
              --replace-fail 'ptr - offset' '(char *)ptr - offset' \
              --replace-quiet 'static __thread volatile uint64_t xoshiro_s[4];' 'static volatile uint64_t xoshiro_s[4];'
          '';
          # Prepended: upstream's preBuild is where prebuildify compiles. gyp's
          # Makefile compiles .c with $(CC); cc-rs (cargo) prefers CC_<target>,
          # which stays gcc.
          preBuild = ''
            export CC_${lib.replaceStrings [ "-" ] [ "_" ] stdenv.hostPlatform.rust.rustcTarget}=$CC
            export CC="${final.compcertCC}/bin/cc -D_GNU_SOURCE -flongdouble"
            export NIX_LDFLAGS="''${NIX_LDFLAGS:-} ${compcertRuntime}"
          ''
          + (old.preBuild or "");
          postBuild =
            (old.postBuild or "")
            + assertCompcertObject "build/Release/obj.target/sqlcipher/deps/sqlcipher/sqlite3.o";
          # Upstream's own test suite (memory + on-disk, plaintext + keyed),
          # against the ccomp-built addon. nixpkgs doesn't run it.
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            pnpm exec vitest run --pool threads
            runHook postCheck
          '';
        });
      in
      prev.signal-desktop.overrideAttrs (old: {
        pname = "signal-desktop-compcert";
        preBuild =
          let
            replaced = lib.replaceStrings [ "${orig}" ] [ "${signal-sqlcipher}" ] old.preBuild;
          in
          # fail loudly if upstream stops copying the addon this way
          assert replaced != old.preBuild;
          replaced
          # nixpkgs replaces only the node_modules/@signalapp/sqlcipher symlink,
          # but electron-builder packages pnpm deps from node_modules/.pnpm, so
          # stock signal-desktop ships the npm prebuilt addon. Replace it there.
          + ''
            for d in node_modules/.pnpm/@signalapp+sqlcipher@*/node_modules/@signalapp/sqlcipher; do
              rm -rf "$d/prebuilds"
              cp -r ${signal-sqlcipher}/prebuilds "$d/prebuilds"
              chmod -R u+w "$d/prebuilds"
            done
          '';
        # The packaged addon must be byte-identical to the ccomp build.
        postInstall = (old.postInstall or "") + ''
          packaged=$(find $out -name '@signalapp+sqlcipher.node')
          built=$(find ${signal-sqlcipher}/prebuilds -name '@signalapp+sqlcipher.node')
          test -n "$packaged"
          cmp "$packaged" "$built"
        '';
        passthru = old.passthru // {
          inherit signal-sqlcipher;
        };
      });
  }
