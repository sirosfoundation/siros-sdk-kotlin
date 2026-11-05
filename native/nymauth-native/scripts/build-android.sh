#!/usr/bin/env bash
# Builds nymauth-native for Android and publishes it to the local Maven repository (~/.m2), where the
# SDK's build finds it (mavenLocal), as org.siros:nymauth-native:<version>:
#
#   build/jni/<abi>/libnymauth_native.so     arm64-v8a (phones) and x86_64 (emulators); release, LTO
#   build/kotlin/uniffi/nymauth_native/      the UniFFI Kotlin bindings, which the SDK vendors
#   build/nymauth-native-<version>.aar       the .so files and license/notice inventories
#
# With --demo-issuer it also builds the ZKP demo wallet's BBS demo issuer (demo-issuer/, DEMO ONLY, never an
# SDK dependency) the same way, as org.siros:nymauth-demo-issuer:<version>, with its bindings in
# demo-issuer/build/kotlin/uniffi/nymauth_demo_issuer/ for the demo app to vendor.
#
# Needs: rustup targets aarch64-linux-android and x86_64-linux-android, cargo-ndk,
# cargo-bundle-licenses 5.0.0, and an Android NDK (ANDROID_NDK_HOME, or the newest under
# $ANDROID_HOME/ndk). Cargo fetches the pinned nym-longfellow and
# nym-bbs git dependencies; no sibling checkout is required.
# armeabi-v7a is not built: Google's runtime needs PMULL (AArch64) or PCLMULQDQ (x86-64).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
cd "$here"
api="${ANDROID_API:-28}"
demo_issuer=false
for arg in "$@"; do
  case "$arg" in
    --demo-issuer) demo_issuer=true ;;
    *) echo "build-android: unknown argument $arg (use --demo-issuer)"; exit 1 ;;
  esac
done

# A RUSTFLAGS variable would replace .cargo/config.toml's +aes,+sha2 (PMULL), without which
# Google's GF(2^128) arithmetic does not build for AArch64.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS

ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
fi
[ -d "${ANDROID_NDK_HOME:-}" ] || { echo "build-android: no NDK (set ANDROID_NDK_HOME)"; exit 1; }
export ANDROID_NDK_HOME
command -v cargo-ndk >/dev/null || { echo "build-android: cargo install cargo-ndk"; exit 1; }
command -v cargo-bundle-licenses >/dev/null || { echo "build-android: cargo install cargo-bundle-licenses"; exit 1; }

# arm64-v8a always; x86_64 (emulators) when its Rust target is installed.
abis=(-t arm64-v8a)
if rustup target list --installed 2>/dev/null | grep -q '^x86_64-linux-android$'; then
  abis+=(-t x86_64)
else
  echo "(x86_64 skipped: rustup target add x86_64-linux-android to build it)"
fi
objdump="$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-objdump 2>/dev/null | head -1 || true)"

# build <crate dir> <library name> <artifact id> <manifest package> <check pmull: true/false>
build() {
  local dir="$1" lib="$2" artifact="$3" package="$4" pmull="$5"
  local notice="$here/NOTICE"
  local description="Native nymauth provers for the SIROS SDKs"
  if [ "$artifact" = nymauth-demo-issuer ]; then
    notice="$here/demo-issuer/NOTICE"
    description="Native nymauth BBS demo issuer for the SIROS SDKs"
  fi
  (
    cd "$dir"
    local version
    version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
    rm -rf build && mkdir -p build/jni build/kotlin build/aar
    echo "== $artifact $version: native libraries (API $api)"
    cargo ndk "${abis[@]}" -P "$api" -o build/jni build --release --lib --locked

    if [ "$pmull" = true ] && [ -n "$objdump" ]; then
      local n
      n="$("$objdump" -d "build/jni/arm64-v8a/lib$lib.so" | grep -c pmull || true)"
      echo "arm64-v8a: $n pmull instructions"
      [ "$n" -gt 0 ] || { echo "build-android: no pmull in the arm64 library (RUSTFLAGS?)"; exit 1; }
    fi

    echo "== $artifact: Kotlin bindings"
    cargo build --release --lib --locked
    local host=""
    for f in "target/release/lib$lib.dylib" "target/release/lib$lib.so"; do
      if [ -f "$f" ]; then host="$f"; break; fi
    done
    [ -n "$host" ] || { echo "build-android: no host library in $dir/target/release"; exit 1; }
    cargo run --release --locked --features bindgen --bin uniffi-bindgen -- generate --library "$host" --language kotlin --out-dir build/kotlin

    echo "== $artifact: AAR"
    mkdir -p build/aar/jni build/aar/licenses build/aar-classes/META-INF
    cp -R build/jni/* build/aar/jni/
    cp "$repo_root/LICENSE" build/aar/LICENSE
    cp "$notice" build/aar/NOTICE
    cp "$here"/licenses/* build/aar/licenses/
    for abi in "${abis[@]}"; do
      [ "$abi" = "-t" ] && continue
      case "$abi" in
        arm64-v8a) target=aarch64-linux-android ;;
        x86_64) target=x86_64-linux-android ;;
        *) echo "build-android: unsupported ABI $abi"; exit 1 ;;
      esac
      python3 "$here/scripts/license_inventory.py" --target "$target" \
        --manifest-path Cargo.toml \
        --output "build/aar/licenses/THIRD_PARTY_LICENSES-$target.json"
    done
    echo "<?xml version=\"1.0\" encoding=\"utf-8\"?><manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"$package\"/>" > build/aar/AndroidManifest.xml
    printf 'Manifest-Version: 1.0\n' > build/aar-classes/META-INF/MANIFEST.MF
    (cd build/aar-classes && zip -qr ../aar/classes.jar .)
    (cd build/aar && zip -qr "../$artifact-$version.aar" .)

    echo "== mavenLocal: org.siros:$artifact:$version"
    local repo="$HOME/.m2/repository/org/siros/$artifact/$version"
    mkdir -p "$repo"
    cp "build/$artifact-$version.aar" "$repo/$artifact-$version.aar"
    cat > "$repo/$artifact-$version.pom" <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.siros</groupId>
  <artifactId>$artifact</artifactId>
  <version>$version</version>
  <packaging>aar</packaging>
  <name>$artifact</name>
  <description>$description</description>
  <url>https://github.com/sirosfoundation/siros-sdk-kotlin</url>
  <licenses>
    <license>
      <name>BSD 2-Clause License</name>
      <url>https://opensource.org/license/bsd-2-clause</url>
      <distribution>repo</distribution>
    </license>
  </licenses>
  <developers>
    <developer>
      <organization>SIROS Foundation</organization>
      <organizationUrl>https://siros.org</organizationUrl>
    </developer>
  </developers>
  <scm>
    <url>https://github.com/sirosfoundation/siros-sdk-kotlin</url>
    <connection>scm:git:https://github.com/sirosfoundation/siros-sdk-kotlin.git</connection>
    <developerConnection>scm:git:ssh://git@github.com/sirosfoundation/siros-sdk-kotlin.git</developerConnection>
  </scm>
  <dependencies>
    <dependency>
      <groupId>net.java.dev.jna</groupId>
      <artifactId>jna</artifactId>
      <version>5.19.1</version>
      <type>aar</type>
    </dependency>
  </dependencies>
</project>
POM
    python3 "$here/scripts/validate-artifact.py" "build/$artifact-$version.aar" "$repo/$artifact-$version.pom" "$artifact" "$version"
    ls -la build/jni/*/"lib$lib.so" "$repo"
    echo "Kotlin bindings: $dir/build/kotlin/uniffi/$lib/$lib.kt"
  )
}

build . nymauth_native nymauth-native org.siros.nymauthnative true
if [ "$demo_issuer" = true ]; then
  build demo-issuer nymauth_demo_issuer nymauth-demo-issuer org.siros.nymauthdemoissuer false
fi
