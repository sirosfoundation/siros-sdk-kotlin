# Building and using PR-built native libraries (nymauth)

The `circuit_zk` prover for the `nymauth-*` circuits runs in two native libraries, `zk-cred-vega` (`vega-nymauth`) and
`zk-cred-longfellow` (`longfellow-nymauth`). Their nymauth entry points are in open pull requests (both
`feat/nymauth-prove`, PR #13). Until those are released, build the AARs from the PR heads and point Gradle at them.

## Pins

The SDK is built against exactly these commits (full SHAs; check a PR's head before building, it can move):

| Library | Commit | Version built as |
|---|---|---|
| `zk-cred-vega` | `d6f0955bf60379e4e81c242e13b5ecbd8e28a271` | `0.0.7` (the crate says `0.0.6`, which is already released without nymauth; a build under that version would collide with the released AAR in `~/.m2` and the Gradle cache) |
| `zk-cred-longfellow` | `cf2eba996ba1fac247539d515d8bab502da48f94` | `0.1.2` (the crate says `0.1.1`; it is built under the next version so it cannot be mistaken for the released AAR) |

The UniFFI Kotlin bindings vendored under `sdk/credentials/src/main/kotlin/uniffi/` are generated from these builds. They check
the library's API checksums when it loads, so a binding and a library from different builds do not load: the version
properties below and the vendored files move together.

## Build

```
git -C <zk-cred-vega> checkout d6f0955bf60379e4e81c242e13b5ecbd8e28a271
git -C <zk-cred-longfellow> checkout cf2eba996ba1fac247539d515d8bab502da48f94
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.3.13750724     # an installed NDK
tools/build-native-aars.sh --vega <zk-cred-vega> --longfellow <zk-cred-longfellow> [--vendor]
```

This needs `cargo`, `cargo-ndk`, the NDK and the rustup targets `aarch64-linux-android`, `armv7-linux-androideabi`,
`x86_64-linux-android`. It writes a Maven directory (default `build/native-repo`). `--vendor` regenerates the Kotlin bindings
from the built libraries.

## Use

```
./gradlew -PsirosNativeRepo=$PWD/build/native-repo :sample-app:installDebug
```

`sirosNativeRepo` adds that directory as the first repository (`settings.gradle.kts`). It can also go in
`~/.gradle/gradle.properties`. The dependency versions default to the ones above; `-PzkCredVegaVersion=` and
`-PzkCredLongfellowVersion=` override them. Nothing is published and `~/.m2` is not touched.

## Android NDK status

See the table in the pull request description (updated with every build of these pins).

## CI and release coordinates

`checkNativeLibraries` (runs before every build of the SDK modules) fails with the coordinates and the way out, instead of a
resolution error in a compile task, when an AAR cannot be resolved, and when it resolves to an older build of the same
version that has no nymauth entry points. For CI to build without `-PsirosNativeRepo` these must be published to GitHub
Packages (each library's own Maven repository), from the merged and tagged native PRs:

- `org.siros:zk-cred-vega:0.0.7` (the PR branch's Cargo.toml still says 0.0.6, which is released and has no nymauth: bump it to 0.0.7 before tagging)
- `org.siros:zk-cred-longfellow:0.1.2` (Cargo.toml says 0.1.1: bump to 0.1.2 before tagging)

and the vendored bindings regenerated from those tagged builds, with `zkCredVegaVersion` / `zkCredLongfellowVersion` defaults
in `sdk/credentials/build.gradle.kts` matching.

## The matcher at rulebook v0.4 (`zkp_req`)

The shared matcher (`org.siros:siros-dc-matcher`) names the presentation `zkp_req` from siros-dc-matcher pull request 50
(merged as `93047bc7b8a22117fbc9b4c8cd59ce7cd742e8d3`, no release yet; the sources are identical to the PR head `69e6be128340c6baed57ca16256956d5107b87ac` the local build below was made from), and a blob built by an older matcher declines `zkp_req`, so the
wallet's registered blob and the matcher asset move together. That matcher is not released, so the SDK builds against a local
build under the coordinates `org.siros:siros-dc-matcher:0.11.0-pr50.69e6be1` (`sirosDcMatcherVersion` in
`sdk/credentials/build.gradle.kts`; the crate itself still says `0.10.0`, which is released and would collide):

```
git -C <siros-dc-matcher> checkout 93047bc7b8a22117fbc9b4c8cd59ce7cd742e8d3
cd <siros-dc-matcher> && make aar pom bindings-kotlin     # cargo, cargo-ndk, the NDK, targets wasm32-wasip1 and the Android ones
V=0.11.0-pr50.69e6be1; D=<repo>/org/siros/siros-dc-matcher/$V; mkdir -p $D
cp target/siros_dc_matcher_ffi-0.10.0.aar $D/siros-dc-matcher-$V.aar
sed "s|<version>0.10.0</version>|<version>$V</version>|" target/siros-dc-matcher-0.10.0.pom > $D/siros-dc-matcher-$V.pom
cp bindings/kotlin/uniffi/siros_dc_matcher_ffi/siros_dc_matcher_ffi.kt <sdk>/sdk/credentials/src/main/kotlin/uniffi/siros_dc_matcher_ffi/
./gradlew -PsirosNativeRepo=<repo> ...        # <repo> also holds zk-cred-vega 0.0.7 and zk-cred-longfellow 0.1.2
```

Re-pin to the release (version, vendored bindings, `spec/zkp-req-vectors`) once the matcher pull request is merged and released.
CI cannot resolve this coordinate until then.
