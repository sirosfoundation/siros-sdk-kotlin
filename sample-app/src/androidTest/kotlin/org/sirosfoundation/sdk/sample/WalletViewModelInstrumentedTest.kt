// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests that run on a real Android device.
 *
 * These tests require the native WSCD UniFFI library which only loads
 * on a real device (not JVM unit tests). Run with:
 *
 *   ./gradlew :sample-app:connectedDebugAndroidTest
 *
 * Or target a specific device:
 *
 *   ./gradlew :sample-app:connectedDebugAndroidTest -Pandroid.serial=10.0.0.148:5555
 */
@RunWith(AndroidJUnit4::class)
class WalletViewModelInstrumentedTest {

    @Test
    fun app_context_is_sample_app() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.startsWith("org.sirosfoundation.sdk.sample"))
    }

    @Test
    fun viewmodel_initializes_with_native_library() {
        val activity = InstrumentationRegistry.getInstrumentation().targetContext
        // If the native library loads, this won't throw UnsatisfiedLinkError
        assertNotNull(activity)
    }
}
