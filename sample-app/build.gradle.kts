plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.compiler)
}

android {
    namespace = "org.siros.sdk.sample"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.siros.sdk.sample"
        minSdk = 28
        targetSdk = 35
        versionCode = 6
        versionName = "0.2.2"

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
            buildConfigField("String", "ENGINE_URL", "\"\"")
            buildConfigField("String", "ISSUER_PROXY_URL", "\"\"")
            buildConfigField("boolean", "R2PS_ENABLED", "false")
            buildConfigField("boolean", "SHOW_PRE_LOGIN_SETTINGS", "true")
        }
        debug {
            // Allow connecting to local backend over cleartext for development
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            // Waydroid reaches host-mapped wallet backend via gateway + wallet-proxy
            buildConfigField("String", "DEFAULT_BACKEND_URL", "\"http://127.0.0.1:8080\"")
            buildConfigField("String", "ENGINE_URL", "\"http://127.0.0.1:8082\"")
            // Rewrite Docker-internal issuer URLs to the host-accessible proxy
            buildConfigField("String", "ISSUER_PROXY_URL", "\"http://192.168.240.1:8091\"")
            // Enable WSCD-backed signing via R2PS in debug builds
            // Requires siros-wscd-manager native lib built with r2ps feature
            buildConfigField("boolean", "R2PS_ENABLED", "false")
            buildConfigField("boolean", "SHOW_PRE_LOGIN_SETTINGS", "true")
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

    // CBOR codec for CTAP2 USB HID transport (FIDO2 plugin)
    implementation("com.upokecenter:cbor:4.5.4")

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
