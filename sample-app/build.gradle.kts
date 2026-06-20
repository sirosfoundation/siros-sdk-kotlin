plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.compiler)
}

android {
    namespace = "org.sirosfoundation.sdk.sample"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.sirosfoundation.sdk.sample"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            manifestPlaceholders["usesCleartextTraffic"] = "false"
            buildConfigField("String", "DEFAULT_BACKEND_URL", "\"https://wallet.sirosid.dev\"")
            buildConfigField("String", "ISSUER_PROXY_URL", "\"\"")
        }
        debug {
            // Allow connecting to local backend over cleartext for development
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            // Waydroid reaches host-mapped wallet backend via gateway + wallet-proxy
            buildConfigField("String", "DEFAULT_BACKEND_URL", "\"http://192.168.240.1:8090\"")
            // Rewrite Docker-internal issuer URLs to the host-accessible proxy
            buildConfigField("String", "ISSUER_PROXY_URL", "\"http://192.168.240.1:8091\"")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
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
    implementation(project(":sdk:wallet"))
    implementation(project(":sdk:keystore"))
    implementation(project(":sdk:passkey-provider"))

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.okhttp)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.ui.tooling.preview)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.timber)

    // QR code scanning
    implementation(libs.camerax.core)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.mlkit.barcode)

    // Credential image loading
    implementation(libs.coil.compose)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
}
