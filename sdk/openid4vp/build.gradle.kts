plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.openid4vp"
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

// A backend-free OpenID4VP client: fetches and checks a signed request, and posts the encrypted response itself. It
// depends on the modules below the wallet engine only (no transport, auth, flow or wallet).
dependencies {
    // AuthorizationResponseEncryption, MdocDeviceResponseBuilder, CircuitZkPresenter (and, through it, credentials).
    api(project(":sdk:keystore"))
    api(project(":sdk:credentials"))
    api(libs.kotlinx.serialization.json)
    api(libs.okhttp)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.nimbus.jose.jwt)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
