plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.sirosfoundation.sdk.keystore"
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
    implementation(project(":sdk:auth"))
    implementation(project(":sdk:credentials"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.play.integrity)
    implementation(libs.timber)

    // siros-wscd-manager UniFFI bindings (AAR from local maven or CI artifact).
    // The AAR is built by `make aar` in the siros-wscd-manager crate.
    // For local development, publish to mavenLocal:
    //   cd siros-wscd-manager && make aar && make publish-local
    implementation("org.sirosfoundation:siros-wscd-manager:0.1.0")
    // JNA is required by UniFFI-generated Kotlin bindings.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
}
