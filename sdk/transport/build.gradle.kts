plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.transport"
    compileSdk = 36

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
    // The wallet-core AAR's version: MUST match the vendored UniFFI bindings
    // (uniffi/engine_adapter_sdk) - both come from the same wallet-core
    // release, bump them together (issue #396).
    val walletCoreVersion: String = providers.gradleProperty("walletCoreVersion").getOrElse("0.2.1")

    // `api`, not `implementation`: FlowStartMessage.authorizationDetails is a
    // public field of type AuthorizationDetail, so a consumer of this module
    // needs that type on its compile classpath.
    api(project(":sdk:credentials"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.okhttp)
    implementation(libs.timber)
    // The LOCAL WMP engine's native library (libengine_adapter_sdk.so) -
    // published per release tag by siros-wallet-core's release.yml, consumed
    // here so the in-process engine mode ships its .so with the SDK build
    // instead of the hand-built jniLibs workaround (issue #396). The version
    // MUST match the vendored UniFFI bindings (uniffi/engine_adapter_sdk):
    // both come from the same wallet-core release - bump them together.
    implementation("org.siros:siros-wallet-core:$walletCoreVersion") {
        // The AAR's POM carries JNA as a plain jar; this SDK consumes
        // net.java.dev.jna:jna:5.19.1@aar (sdk/keystore's wscd wiring) -
        // without the exclude the two packagings duplicate every class.
        exclude(group = "net.java.dev.jna", module = "jna")
    }

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.turbine)
    testImplementation(libs.okhttp.mockwebserver)
}
