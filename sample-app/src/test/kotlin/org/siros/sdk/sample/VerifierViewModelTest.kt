// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VerifierViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(dispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    @Test
    fun invalidEngagementNeedsNoWalletOrTransport() = runTest {
        var transportCalls = 0
        val viewModel = VerifierViewModel(
            transportFactory = { _, _ ->
                transportCalls++
                error("transport must not start")
            },
        )

        viewModel.onQrScanned("https://not-an-mdoc-engagement")
        advanceUntilIdle()

        assertEquals(0, transportCalls)
        assertNotNull(viewModel.state.value.error)
        assertTrue(viewModel.state.value.documents.isEmpty())
        assertFalse(viewModel.state.value.busy)
    }

    @Test
    fun startingANewScanClearsStaleResults() = runTest {
        val viewModel = VerifierViewModel(
            transportFactory = { _, _ -> error("not used") },
        )
        viewModel.onQrScanned("invalid")
        advanceUntilIdle()
        assertNotNull(viewModel.state.value.error)

        viewModel.startScan()

        assertTrue(viewModel.state.value.scanning)
        assertEquals(null, viewModel.state.value.error)
        assertTrue(viewModel.state.value.documents.isEmpty())
        viewModel.cancelScan()
        assertFalse(viewModel.state.value.scanning)
    }
}
