#!/usr/bin/env bash
# Builds nymauth-native for Android and publishes it to the local Maven repository (~/.m2), where the
# SDK's build finds it (mavenLocal), as org.siros:nymauth-native:<version>:
#
#   build/jni/<abi>/libnymauth_native.so     arm64-v8a (phones) and x86_64 (emulators); release, LTO
#   build/kotlin/uniffi/nymauth_native/      the UniFFI Kotlin bindings, which the SDK vendors
#   build/nymauth-native-<version>.aar       the .so files only (as zk-cred-longfellow's AAR)
#
# Needs: rustup targets aarch64-linux-android and x86_64-linux-android, cargo-ndk, an Android NDK
# (ANDROID_NDK_HOME, or the newest under $ANDROID_HOME/ndk), and readdit-demo (nym-longfellow) checked out
# next to siros-sdk-kotlin.
# armeabi-v7a is not built: Google's runtime needs PMULL (AArch64) or PCLMULQDQ (x86-64).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
api="${ANDROID_API:-28}"

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
[ -d ../../../readdit-demo/native/longfellow/nym-longfellow ] || { echo "build-android: readdit-demo (nym-longfellow) is missing next to siros-sdk-kotlin"; exit 1; }

rm -rf build && mkdir -p build/jni build/kotlin build/aar
# arm64-v8a always; x86_64 (emulators) when its Rust target is installed.
abis=(-t arm64-v8a)
if rustup target list --installed 2>/dev/null | grep -q '^x86_64-linux-android$'; then
  abis+=(-t x86_64)
else
  echo "(x86_64 skipped: rustup target add x86_64-linux-android to build it)"
fi
echo "== native libraries (API $api)"
cargo ndk "${abis[@]}" -P "$api" -o build/jni build --release --lib --locked

objdump="$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-objdump 2>/dev/null | head -1)"
if [ -n "$objdump" ]; then
  n="$("$objdump" -d build/jni/arm64-v8a/libnymauth_native.so | grep -c pmull || true)"
  echo "arm64-v8a: $n pmull instructions"
  [ "$n" -gt 0 ] || { echo "build-android: no pmull in the arm64 library (RUSTFLAGS?)"; exit 1; }
fi

echo "== Kotlin bindings"
cargo build --release --lib --locked
lib=""
for f in target/release/libnymauth_native.dylib target/release/libnymauth_native.so; do
  if [ -f "$f" ]; then lib="$f"; break; fi
done
[ -n "$lib" ] || { echo "build-android: no host library in target/release"; exit 1; }
cargo run --release --locked --features bindgen --bin uniffi-bindgen -- generate --library "$lib" --language kotlin --out-dir build/kotlin

echo "== AAR"
mkdir -p build/aar/jni build/aar-classes/META-INF
cp -R build/jni/* build/aar/jni/
echo '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.siros.nymauthnative"/>' > build/aar/AndroidManifest.xml
printf 'Manifest-Version: 1.0\n' > build/aar-classes/META-INF/MANIFEST.MF
(cd build/aar-classes && zip -qr ../aar/classes.jar .)
(cd build/aar && zip -qr "../nymauth-native-$version.aar" .)

echo "== mavenLocal: org.siros:nymauth-native:$version"
repo="$HOME/.m2/repository/org/siros/nymauth-native/$version"
mkdir -p "$repo"
cp "build/nymauth-native-$version.aar" "$repo/nymauth-native-$version.aar"
cat > "$repo/nymauth-native-$version.pom" <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.siros</groupId>
  <artifactId>nymauth-native</artifactId>
  <version>$version</version>
  <packaging>aar</packaging>
  <dependencies>
    <dependency>
      <groupId>net.java.dev.jna</groupId>
      <artifactId>jna</artifactId>
      <version>5.14.0</version>
      <type>aar</type>
    </dependency>
  </dependencies>
</project>
POM
ls -la build/jni/*/libnymauth_native.so "$repo"
echo "Kotlin bindings: build/kotlin/uniffi/nymauth_native/nymauth_native.kt"
