// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertNull
import org.junit.Test

class CredentialSecretSeedSourceTest {
    @Test
    fun `until the storage side lands no credential has a secret seed`() {
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(1L))
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(Long.MAX_VALUE))
    }
}
