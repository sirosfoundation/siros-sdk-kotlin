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
    // this line to origin/main. zk-cred-vega is a private repo with no
    // GitHub Release/published artifact yet (per
    // ~/.claude/plans/zk-cred-vega-sdk-handoff.md's "What's NOT ready yet"
    // #4) - CI cannot resolve this, only a local `make aar && make
    // publish-local` (already done for 0.1.0 as of this branch). Uncomment
    // only once a real released version exists to depend on.
    implementation("org.siros:zk-cred-vega:0.1.0")

    // JNA is required by UniFFI-generated Kotlin bindings.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
}
