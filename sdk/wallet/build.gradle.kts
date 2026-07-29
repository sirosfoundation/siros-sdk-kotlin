plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.wallet"
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
    // Internal SDK modules — transitive, so the app gets everything via :sdk:wallet
    api(project(":sdk:transport"))
    api(project(":sdk:auth"))
    api(project(":sdk:keystore"))
    api(project(":sdk:flow"))
    api(project(":sdk:credentials"))
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
}
