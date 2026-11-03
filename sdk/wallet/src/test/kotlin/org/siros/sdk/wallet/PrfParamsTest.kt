// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.auth.PrfOutput
import org.siros.sdk.keystore.JweKeystore

/** The container of an account with two passkeys, each with its own PRF and HKDF values. */
internal class TwoPasskeyAccount {
    val firstCred = byteArrayOf(1, 1)
    val secondCred = byteArrayOf(2, 2)
    val firstPrfSalt = ByteArray(32) { 1 }
    val secondPrfSalt = ByteArray(32) { 2 }
    val firstHkdfSalt = ByteArray(32) { 11 }
    val secondHkdfSalt = ByteArray(32) { 22 }
    val firstHkdfInfo = "first info".toByteArray()
    val secondHkdfInfo = "second info".toByteArray()
    val firstPrf = ByteArray(32) { 5 }
    val secondPrf = ByteArray(32) { 6 }
    val container: ByteArray = kotlinx.coroutines.runBlocking {
        val ks = JweKeystore()
        ks.unlock(firstPrf, ByteArray(0), firstHkdfSalt, firstHkdfInfo, firstPrfSalt)
        ks.setCredentialId(firstCred)
        ks.preparePrfKey(secondCred, secondPrf, secondPrfSalt, secondHkdfSalt, secondHkdfInfo).container
    }
}

class PrfParamsTest {
    private val a = TwoPasskeyAccount()
    private val default = "default".toByteArray()
    private val storedPrf = ByteArray(32) { 91 }
    private val storedHkdf = ByteArray(32) { 92 }
    private val storedInfo = "stored".toByteArray()

    private fun login(credId: ByteArray, data: ByteArray = a.container, recovered: PrfParams? = null) = resolveLoginPrfParams(
        data, credId, recovered, storedPrf, storedHkdf, storedInfo, default,
    )

    @Test
    fun login_uses_the_logging_in_passkeys_own_entry() {
        val p = login(a.secondCred)
        assertArrayEquals(a.secondPrfSalt, p.prfSalt)
        assertArrayEquals(a.secondHkdfSalt, p.hkdfSalt)
        assertArrayEquals(a.secondHkdfInfo, p.hkdfInfo)
        assertArrayEquals(a.firstHkdfSalt, login(a.firstCred).hkdfSalt)
    }

    @Test
    fun login_prefers_recovered_values_then_falls_back_to_the_stored_ones() {
        val r = PrfParams(ByteArray(32) { 71 }, ByteArray(32) { 72 }, "rec".toByteArray())
        assertSame(r.hkdfSalt, login(a.secondCred, recovered = r).hkdfSalt)
        // Unknown credential, empty or unparseable container: the session store's values.
        for (data in listOf(a.container, ByteArray(0), "not json".toByteArray())) {
            val p = login(byteArrayOf(9, 9), data)
            assertArrayEquals(storedPrf, p.prfSalt)
            assertArrayEquals(storedHkdf, p.hkdfSalt)
            assertArrayEquals(storedInfo, p.hkdfInfo)
        }
    }

    @Test
    fun login_generates_fresh_salts_for_a_new_account() {
        val p = resolveLoginPrfParams(ByteArray(0), a.firstCred, null, null, null, null, default)
        assertEquals(32, p.hkdfSalt.size)
        assertArrayEquals(default, p.hkdfInfo)
    }

    private suspend fun unlock(credId: ByteArray?, ceremonySalt: ByteArray?, evaluated: MutableList<List<Any>>, data: ByteArray = a.container) =
        resolveUnlockPrf(
            data, credId, "rp", ceremonySalt, PrfOutput(a.firstPrf), storedHkdf, storedInfo, default,
        ) { id, salt, rp -> evaluated += listOf(id, salt, rp); PrfOutput(a.secondPrf) }

    @Test
    fun unlock_with_the_second_passkey_uses_its_entry_and_re_evaluates_the_prf() = runTest {
        val evaluated = mutableListOf<List<Any>>()
        val u = unlock(a.secondCred, a.firstPrfSalt, evaluated)
        assertArrayEquals(a.secondPrf, u.prfOutput.first)
        assertArrayEquals(a.secondHkdfSalt, u.hkdfSalt)
        assertArrayEquals(a.secondHkdfInfo, u.hkdfInfo)
        assertEquals(1, evaluated.size)
        assertArrayEquals(a.secondPrfSalt, evaluated[0][1] as ByteArray)
        assertEquals("rp", evaluated[0][2])
    }

    @Test
    fun unlock_with_the_stored_passkey_keeps_the_ceremonys_output() = runTest {
        val evaluated = mutableListOf<List<Any>>()
        val u = unlock(a.firstCred, a.firstPrfSalt, evaluated)
        assertArrayEquals(a.firstPrf, u.prfOutput.first)
        assertArrayEquals(a.firstHkdfSalt, u.hkdfSalt)
        assertEquals(0, evaluated.size)
    }

    @Test
    fun unlock_falls_back_to_the_stored_values_and_refuses_without_any() = runTest {
        val evaluated = mutableListOf<List<Any>>()
        for (credId in listOf(null, byteArrayOf(9))) {
            val u = unlock(credId, a.firstPrfSalt, evaluated)
            assertArrayEquals(a.firstPrf, u.prfOutput.first)
            assertArrayEquals(storedHkdf, u.hkdfSalt)
            assertArrayEquals(storedInfo, u.hkdfInfo)
        }
        assertEquals(0, evaluated.size)
        try {
            resolveUnlockPrf(ByteArray(0), null, null, null, PrfOutput(a.firstPrf), null, null, default) { _, _, _ -> error("no") }
            fail("no HKDF salt anywhere must refuse")
        } catch (e: org.siros.sdk.credentials.WalletException) {
            assertNull(e.cause)
        }
    }
}
