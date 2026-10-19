# Building and using PR-built native libraries (nymauth)

The `circuit_zk` prover for the `nymauth-*` circuits runs in two native libraries, `zk-cred-vega` (`vega-nymauth`) and
`zk-cred-longfellow` (`longfellow-nymauth`). Their nymauth entry points are in open pull requests (both
`feat/nymauth-prove`, PR #13). Until those are released, build the AARs from the PR heads and point Gradle at them.

## Pins

The SDK is built against exactly these commits (full SHAs; check a PR's head before building, it can move):

| Library | Commit | Version built as |
|---|---|---|
| `zk-cred-vega` | `d6f0955bf60379e4e81c242e13b5ecbd8e28a271` | `0.0.6` |
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
