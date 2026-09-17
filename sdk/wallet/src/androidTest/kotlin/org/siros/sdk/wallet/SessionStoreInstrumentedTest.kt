// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * [SessionStore.clearAccount] must keep the instance key (SID-AUTH-06).
 *
 * On a device rather than in a JVM unit test because [SessionStore] is backed
 * by `EncryptedSharedPreferences`, which needs a real `Context` and the
 * platform keystore - there is nothing to fake that would still exercise the
 * prefix-filtering this class actually does. The Swift port covers the same
 * behaviour in plain unit tests (`SessionStoreTests`).
 *
 * What is at stake: the instance key's JWK thumbprint IS this installation's
 * wallet instance id at the backend. Clearing it on logout would mint a new
 * key at the next login, register a new - active - instance, and so let a
 * **suspended** installation walk away from its own suspension by logging out
 * and back in.
 */
@RunWith(AndroidJUnit4::class)
class SessionStoreInstrumentedTest {

    private lateinit var store: SessionStore

    @Before
    fun setUp() {
        store = SessionStore(InstrumentationRegistry.getInstrumentation().targetContext)
        store.clearAll()
    }

    @Test
    fun clearAccount_keeps_the_instance_key() {
        store.activeAccountId = "default:user-1"
        store.instanceKeyId = "instance-key-1"
        store.userId = "user-1"

        store.clearAccount()

        assertNull("the session itself is cleared", store.userId)
        assertEquals("the instance key survives a logout", "instance-key-1", store.instanceKeyId)
    }

    @Test
    fun clearAll_removes_the_instance_key() {
        store.activeAccountId = "default:user-1"
        store.instanceKeyId = "instance-key-1"

        store.clearAll()

        store.activeAccountId = "default:user-1"
        assertNull(store.instanceKeyId)
    }

    @Test
    fun instance_keys_are_scoped_per_account() {
        store.activeAccountId = "default:user-1"
        store.instanceKeyId = "key-1"
        store.activeAccountId = "default:user-2"
        store.instanceKeyId = "key-2"

        store.clearAccount()

        assertEquals("key-2", store.instanceKeyId)
        store.activeAccountId = "default:user-1"
        assertEquals("key-1", store.instanceKeyId)
    }
}
