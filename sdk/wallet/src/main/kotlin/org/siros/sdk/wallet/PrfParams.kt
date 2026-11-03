// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.keystore.EncryptedContainer
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.keystore.PrfKeyInfo
import java.security.SecureRandom

/**
 * The values a passkey's PRF output is turned into the keystore key with.
 * Each passkey of an account has its own, stored in its own entry of the
 * private data container.
 */
internal class PrfParams(val prfSalt: ByteArray, val hkdfSalt: ByteArray, val hkdfInfo: ByteArray)

/**
 * The container's PRF entry for [credId], or null when [privateData] is empty,
 * unparseable or has no entry for it.
 */
internal fun findOwnPrfEntry(privateData: ByteArray, credId: ByteArray): PrfKeyInfo? {
    if (privateData.isEmpty()) return null
    return runCatching {
        EncryptedContainer.parse(privateData).prfKeys.firstOrNull { it.credentialId.contentEquals(credId) }
    }.getOrNull()
}

/**
 * Which salts to derive with at login. An account with several passkeys has one
 * PRF entry per passkey, each with its own HKDF salt; the session store holds
 * only one passkey's values, so using them for another passkey unlocks the
 * wrong entry. Order, per value: [recovered] (read from the container just
 * before), the entry of the passkey that logged in, the session store's value,
 * and last a fresh random one (a brand-new account).
 */
internal fun resolveLoginPrfParams(
    privateData: ByteArray,
    credId: ByteArray,
    recovered: PrfParams?,
    storedPrfSalt: ByteArray?,
    storedHkdfSalt: ByteArray?,
    storedHkdfInfo: ByteArray?,
    defaultHkdfInfo: ByteArray,
): PrfParams {
    val own = findOwnPrfEntry(privateData, credId)
    fun random() = ByteArray(32).also { SecureRandom().nextBytes(it) }
    return PrfParams(
        prfSalt = recovered?.prfSalt ?: own?.prfSalt ?: storedPrfSalt ?: random(),
        hkdfSalt = recovered?.hkdfSalt ?: own?.hkdfSalt ?: storedHkdfSalt ?: random(),
        hkdfInfo = recovered?.hkdfInfo ?: own?.hkdfInfo ?: storedHkdfInfo ?: defaultHkdfInfo,
    )
}

/** The PRF output and HKDF values [resolveUnlockPrf] settled on. */
internal class UnlockPrf(val prfOutput: org.siros.sdk.auth.PrfOutput, val hkdfSalt: ByteArray, val hkdfInfo: ByteArray)

/**
 * Which PRF output and HKDF values unlock the keystore after a resume. The
 * unlock ceremony evaluated the PRF with [ceremonyPrfSalt] (the stored
 * passkey's), but the user may have answered with another passkey of the
 * account. That passkey's container entry carries its own PRF salt and HKDF
 * values; when it differs, the PRF is evaluated again with [reEvaluate]
 * (credential id, salt, rpId). Without an entry for [credId] the stored values apply.
 *
 * @throws WalletException when neither the entry nor the session store has an HKDF salt.
 */
internal suspend fun resolveUnlockPrf(
    privateData: ByteArray,
    credId: ByteArray?,
    rpId: String?,
    ceremonyPrfSalt: ByteArray?,
    ceremonyPrfOutput: org.siros.sdk.auth.PrfOutput,
    storedHkdfSalt: ByteArray?,
    storedHkdfInfo: ByteArray?,
    defaultHkdfInfo: ByteArray,
    reEvaluate: suspend (credId: ByteArray, salt: ByteArray, rpId: String) -> org.siros.sdk.auth.PrfOutput,
): UnlockPrf {
    val own = credId?.let { findOwnPrfEntry(privateData, it) }
    val prfOutput = if (own != null && rpId != null && !own.prfSalt.contentEquals(ceremonyPrfSalt)) {
        reEvaluate(credId, own.prfSalt, rpId)
    } else {
        ceremonyPrfOutput
    }
    return UnlockPrf(
        prfOutput = prfOutput,
        hkdfSalt = own?.hkdfSalt ?: storedHkdfSalt ?: throw WalletException("Missing HKDF salt"),
        hkdfInfo = own?.hkdfInfo ?: storedHkdfInfo ?: defaultHkdfInfo,
    )
}
