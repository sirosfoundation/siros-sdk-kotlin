plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.credentials"
    compileSdk = 35

    defaultConfig {
        minSdk = 28
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.timber)
    // Real HTTP client for ZkCircuitClient (mirrors sdk/auth's BackendApiClient usage).
    implementation(libs.okhttp)
    // Real CBOR codec for ISO 18013-5 mdoc parsing (claim extraction/display).
    // `api` (not `implementation`) since sdk/keystore depends on this module
    // and re-exposes CBORObject-typed values from the mdoc parsing model.
    api(libs.upokecenter.cbor)

    // zk-cred-longfellow UniFFI bindings (AAR from local maven or CI
    // release artifact). The AAR is built by `make aar` in that crate.
    // For local development, publish to mavenLocal:
    //   cd zk-cred-longfellow && make aar && make publish-local
    implementation("org.siros:zk-cred-longfellow:0.1.1")

    // zk-cred-vega UniFFI bindings - real GitHub Packages Maven artifact
    // (resolved via GitHubPackagesZkCredVega in settings.gradle.kts), built
    // against sirosfoundation/vega-prover's fork (a 2-line #[serde(skip)]
    // fix shrinking the FFI prep-state from ~356MB to ~100MB so it fits
    // Android's heap ceiling). v0.0.3 carries a real, independently-flagged
    // privacy fix (undisclosed-claim digest concealment) - see
    // VegaProofSystem.kt's own doc comment for the crate's current status.
    // v0.0.4 bumps vega-prover to sirosfoundation/vega-prover@2a7dcb3, a
    // real measured ~35-40% prove() speedup on x86_64 (chunk-overhead fix
    // in bind_and_prepare_poly_ABC_inner) - not yet confirmed on-device.
    implementation("org.siros:zk-cred-vega:0.0.5")

    // zk-cred-bbs UniFFI bindings - blind BBS with Schnorr key binding.
    // Same shape as above: AAR from GitHub Packages (or mavenLocal via
    // `cd zk-cred-bbs && make publish-local`), Kotlin bindings vendored
    // under src/main/kotlin/uniffi/zk_cred_bbs/.
    implementation("org.siros:zk-cred-bbs:0.0.6")

    // JNA is required by UniFFI-generated Kotlin bindings.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // Instrumented tests: the zk-cred-bbs native library ships as .so files
    // inside its AAR, so anything exercising the UniFFI surface has to run
    // on a device or emulator - a JVM unit test cannot load them.
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation(libs.kotlinx.coroutines.test)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
}
