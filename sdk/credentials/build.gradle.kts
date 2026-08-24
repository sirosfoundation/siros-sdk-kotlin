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

    // zk-cred-vega UniFFI bindings - LOCAL DEVELOPMENT ONLY, DO NOT PUSH/MERGE
    // this line to origin/main. zk-cred-vega now has a real GitHub Packages
    // Maven artifact (v0.0.2, resolved via GitHubPackagesZkCredVega in
    // settings.gradle.kts) - built against sirosfoundation/vega-prover's
    // fork (a 2-line #[serde(skip)] fix shrinking the FFI prep-state from
    // ~356MB to ~100MB so it fits Android's heap ceiling). Still blocked on
    // the circuit-artifact/expert-review gating in
    // ~/.claude/plans/zk-cred-vega-sdk-handoff.md's "START HERE" block.
    implementation("org.siros:zk-cred-vega:0.0.2")

    // JNA is required by UniFFI-generated Kotlin bindings.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
}
