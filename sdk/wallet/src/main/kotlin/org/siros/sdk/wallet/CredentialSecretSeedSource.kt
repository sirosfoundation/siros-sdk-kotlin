// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * Where the wallet gets a credential's issuer-delivered `secret_seed` (16 bytes) for a `circuit_zk`
 * presentation whose pseudonym config derives from it (`known-offender-matching-ssc`,
 * `account-recovery-ssc`, `user-managed-pseudonym-xsite-ssc`).
 *
 * INTERNAL SEAM. The storage and receipt side (the issuer delivering the seed in the credential response
 * `credential_metadata`, kept per credential in privatedata) is a follow-up; until it lands the only
 * source is [NONE], so every ssc-based request is refused. The wallet hands the returned array to the
 * presenter, which verifies `SHA256(seed) == ssc` itself, and zeroes the array afterwards; an
 * implementation must therefore return a fresh copy on each call. A source must never log the seed.
 */
internal fun interface CredentialSecretSeedSource {
    /** A fresh copy of the seed of the credential with id [credentialId], or null when none is held. */
    fun secretSeed(credentialId: Long): ByteArray?

    companion object {
        /** No credential has a seed. */
        val NONE = CredentialSecretSeedSource { null }
    }
}
