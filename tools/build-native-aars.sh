#!/usr/bin/env bash
# Builds the zk-cred-vega and zk-cred-longfellow AARs from checkouts of their nymauth PR branches into a plain Maven
# directory, so the SDK / sample app can use them without publishing anything (docs/NATIVE_DEV.md).
#
#   tools/build-native-aars.sh --vega <checkout> --longfellow <checkout> [--out <dir>] [--vendor] [--abis "arm64-v8a ..."]
#
# Each checkout must be AT the pinned full commit (checked, not assumed). --vendor also regenerates the UniFFI Kotlin
# bindings from the built libraries into sdk/credentials/src/main/kotlin/uniffi/ (they must come from the same build as the
# AAR: they check the library's API checksums when it loads). Requires cargo, cargo-ndk, the Android NDK
# (ANDROID_NDK_HOME) and the Android targets of rustup. Output: <out>/org/siros/<artifact>/<version>/.
set -euo pipefail

VEGA_SHA=36ae7a76c004a83e9bfc3ee46dde2f328cc1d852          # sirosfoundation/zk-cred-vega feat/nymauth-threads (nymauth_vega_prove_with), on main after PR #13
LONGFELLOW_SHA=cf2eba996ba1fac247539d515d8bab502da48f94    # sirosfoundation/zk-cred-longfellow PR #13 (feat/nymauth-prove)
VEGA_VERSION=0.0.8                                         # the crate says 0.0.8 (not released yet)
LONGFELLOW_VERSION=0.1.2                                    # the crate says 0.1.1: built under the next version so it cannot be mistaken for the released one

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/build/native-repo"; vega=""; lf=""; vendor=0; abis=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vega) vega="$2"; shift 2;;
    --longfellow) lf="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    --vendor) vendor=1; shift;;
    --abis) abis="$2"; shift 2;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done
[ -n "$vega$lf" ] || { echo "give --vega and/or --longfellow" >&2; exit 2; }
# x86_64 (the emulator ABI) cannot be cross-built on Apple Silicon: vega-prover turns on halo2curves' `asm` for an x86_64
# target, and halo2curves' build script refuses it unless the HOST is x86_64. So on an arm64 Mac only the phone ABIs.
if [ -z "$abis" ] && [ "$(uname -sm)" = "Darwin arm64" ]; then
  abis="arm64-v8a armeabi-v7a"
  echo "Apple Silicon: building $abis only (x86_64 needs an x86_64 host); --abis chooses" >&2
fi

check_sha() { # dir expected
  local have; have="$(git -C "$1" rev-parse HEAD)"
  [ "$have" = "$2" ] || { echo "$1 is at $have, expected $2 (check the PR head before building; it may have moved)" >&2; exit 1; }
  [ -z "$(git -C "$1" status --porcelain --untracked-files=no)" ] || { echo "$1 has local changes" >&2; exit 1; }
}

build() { # dir artifact version crate
  local dir="$1" artifact="$2" version="$3" crate="$4" lib="lib${4//-/_}.so"
  local dest="$out/org/siros/$artifact/$version"
  mkdir -p "$dest"; dest="$(cd "$dest" && pwd)"
  if [ -z "$abis" ]; then
    ( cd "$dir" && make aar pom VERSION="$version" )
    cp "$dir/target/${crate//-/_}-$version.aar" "$dest/$artifact-$version.aar"
  else
    # Only these ABIs: each built by the Makefile's android-<triple> target, then packaged as its `aar` target packages
    # them (jni/<abi>/<lib>.so, a manifest, an empty classes.jar).
    local stage triple; stage="$(mktemp -d)"
    mkdir -p "$stage/aar" "$stage/classes/META-INF"
    for abi in $abis; do
      case "$abi" in
        arm64-v8a) triple=aarch64-linux-android;;
        armeabi-v7a) triple=armv7-linux-androideabi;;
        x86_64) triple=x86_64-linux-android;;
        *) echo "unknown ABI $abi" >&2; exit 2;;
      esac
      ( cd "$dir" && make "android-$triple" )
      mkdir -p "$stage/aar/jni/$abi"
      cp "$dir/target/$triple/release/$lib" "$stage/aar/jni/$abi/"
    done
    ( cd "$dir" && make pom VERSION="$version" )
    printf '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.siros.%s"/>' \
      "${crate//-/}" > "$stage/aar/AndroidManifest.xml"
    printf 'Manifest-Version: 1.0\n' > "$stage/classes/META-INF/MANIFEST.MF"
    ( cd "$stage/classes" && zip -qr ../aar/classes.jar . )
    rm -f "$dest/$artifact-$version.aar"
    ( cd "$stage/aar" && zip -qr "$dest/$artifact-$version.aar" . )
    rm -rf "$stage"
  fi
  cp "$dir/target/$artifact-$version.pom" "$dest/$artifact-$version.pom"
  echo "built $dest${abis:+ (ABIs: $abis)}"
}

vendor_bindings() { # dir crate (generated from the Android arm64 library of the same build)
  local dir="$1" crate="$2" lib="$1/target/aarch64-linux-android/release/lib$2.so"
  ( cd "$dir" && cargo run --release --features uniffi --bin uniffi-bindgen -- generate --library "$lib" --language kotlin --out-dir "$dir/target/kotlin-bindings" )
  mkdir -p "$here/sdk/credentials/src/main/kotlin/uniffi/$crate"
  cp "$dir/target/kotlin-bindings/uniffi/$crate/$crate.kt" "$here/sdk/credentials/src/main/kotlin/uniffi/$crate/$crate.kt"
  if [ "$crate" = zk_cred_vega ]; then
    # The generated NymAuthVegaException variants have a field named `message`, which clashes with Throwable.message and does
    # not compile. Renamed to `detail` in the Kotlin only (UniFFI reads fields by position); the proper fix is a different
    # field name in zk-cred-vega's NymAuthVegaError.
    python3 - "$here/sdk/credentials/src/main/kotlin/uniffi/zk_cred_vega/zk_cred_vega.kt" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = s.index("sealed class NymAuthVegaException")
b = s.index("companion object ErrorHandler", a) if "companion object ErrorHandler" in s[a:] else a + 6000
seg = s[a:b].replace("val `message`: kotlin.String", "val `detail`: kotlin.String").replace('get() = "message=${ `message` }"', 'get() = "message=${ `detail` }"')
s = s[:a] + seg + s[b:]
c = s.index("object FfiConverterTypeNymAuthVegaError") if "object FfiConverterTypeNymAuthVegaError" in s else a
s = s[:c] + s[c:].replace("value.`message`", "value.`detail`", 40)
open(p, "w").write(s)
PY
  fi
  echo "vendored bindings for $crate"
}

if [ -n "$vega" ]; then check_sha "$vega" "$VEGA_SHA"; build "$vega" zk-cred-vega "$VEGA_VERSION" zk-cred-vega; [ $vendor = 1 ] && vendor_bindings "$vega" zk_cred_vega; fi
if [ -n "$lf" ]; then check_sha "$lf" "$LONGFELLOW_SHA"; build "$lf" zk-cred-longfellow "$LONGFELLOW_VERSION" zk-cred-longfellow; [ $vendor = 1 ] && vendor_bindings "$lf" zk_cred_longfellow; fi
echo "Use: ./gradlew -PsirosNativeRepo=$out ..."
