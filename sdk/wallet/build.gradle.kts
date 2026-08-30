plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.wallet"
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
    // Internal SDK modules — transitive, so the app gets everything via :sdk:wallet
    api(project(":sdk:transport"))
    api(project(":sdk:auth"))
    api(project(":sdk:keystore"))
    api(project(":sdk:flow"))
    api(project(":sdk:credentials"))

    // The DC API matcher: the CBOR encoder for the blob a wallet registers,
    // and matcher.wasm itself as an asset. One dependency at one version, so
    // the writer and the reader cannot drift apart.
    implementation("org.siros:siros-dc-matcher:0.1.0")

    // Registry provider API — DigitalCredentialRegistry takes the matcher as
    // a plain ByteArray, which is what makes supplying our own supported
    // rather than a workaround.
    implementation(libs.androidx.credentials.registry.provider)
    implementation(libs.androidx.credentials.registry.provider.play)
    // Only for the stock-matcher fallback path.
    implementation(libs.androidx.credentials.registry.mdoc)
    implementation(libs.androidx.credentials.registry.openid)
    implementation(libs.androidx.credentials.registry.sdjwtvc)

    // JNA, for the UniFFI bindings' native access.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    api(project(":sdk:idv"))

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play)
    implementation(libs.androidx.security.crypto)
    implementation(libs.timber)
    // JWS verification for signed/multisigned DC API JAR requests (Appendix A) -
    // sdk:keystore depends on this too, but only as `implementation`, so it
    // isn't visible here transitively.
    implementation(libs.nimbus.jose.jwt)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.kotlin.reflect)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
