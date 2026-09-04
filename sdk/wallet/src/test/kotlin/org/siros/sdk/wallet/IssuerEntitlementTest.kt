package org.siros.sdk.wallet

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.IssuerEntitlement
import org.siros.sdk.credentials.IssuerEntitlementFinding
import kotlin.reflect.full.callSuspend
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible
import org.siros.sdk.credentials.WalletException

/**
 * The wallet-side half of ARF section 6.6.2.3: the backend decides whether a
 * provider is registered to issue what it offers, and the wallet has to act on
 * that decision rather than merely display it.
 *
 * These tests pin the three states apart, because collapsing any two of them is
 * the failure mode that matters: refused, allowed-with-findings (warn mode),
 * and not checked at all.
 */
class IssuerEntitlementTest {

    private val issuer = "https://issuer.example.com"

    @Test
    fun refusesIssuance_whenTheProviderIsNotEntitled() {
        val entitlement = IssuerEntitlement(
            allowed = false,
            mode = "fail",
            evaluated = true,
            findings = listOf(
                IssuerEntitlementFinding(
                    code = "attestation_type_not_registered",
                    message = "provider is not registered to issue dc+sd-jwt of type \"eu.europa.ec.eudi.pid.1\"",
                    credentialType = "eu.europa.ec.eudi.pid.1",
                ),
            ),
        )

        val e = runCatching { enforce(entitlement) }.exceptionOrNull()
        assertTrue("expected a WalletException, got $e", e is WalletException)
        // The reason has to survive into the message: a bare "not allowed"
        // leaves a user with no way to tell a misconfigured issuer from a
        // genuinely unregistered one.
        assertTrue(
            "message should name the finding, was: ${e?.message}",
            e?.message?.contains("attestation_type_not_registered") == true,
        )
    }

    @Test
    fun allowsIssuance_inWarnMode_evenWithFindings() {
        // Warn is the default until the ARF's 24-month registration obligation
        // bites. Findings are reported; issuance still proceeds.
        val entitlement = IssuerEntitlement(
            allowed = true,
            mode = "warn",
            evaluated = true,
            findings = listOf(
                IssuerEntitlementFinding(
                    code = "no_registration_certificate",
                    message = "issuer metadata carries no registration certificate in issuer_info",
                ),
            ),
        )
        enforce(entitlement)
    }

    @Test
    fun allowsIssuance_whenTheCheckDidNotRun() {
        // A null entitlement means "not checked" - the backend was absent or
        // unreachable. That must not block issuance, and equally must never be
        // recorded anywhere as a pass.
        enforce(null)
    }

    @Test
    fun entitlementForAConfiguration_isNullWhenResolutionFails() {
        // No apiClient and no httpClient: resolution cannot run at all. The
        // helper has to absorb that, or a backend outage becomes an outage for
        // every issuer.
        val wallet = bareWallet()
        val m = SirosWallet::class.declaredMemberFunctions.first { it.name == "issuerEntitlementFor" }
        m.isAccessible = true
        val result = runBlocking { m.callSuspend(wallet, issuer, "eu.europa.ec.eudi.pid.1") }
        assertNull(result)
    }

    @Test
    fun resolvedMetadata_defaultsToNotChecked() {
        // The direct-fetch fallback constructs this with metadata only. If the
        // default were anything but null, an unauthenticated fetch would read
        // downstream as an evaluated pass.
        val resolved = SirosWallet.ResolvedIssuerMetadata(
            metadata = org.siros.sdk.credentials.IssuerMetadata(credentialIssuer = issuer),
        )
        assertNull(resolved.entitlement)
        assertNull(resolved.trusted)
        assertEquals(issuer, resolved.metadata.credentialIssuer)
    }

    private fun enforce(entitlement: IssuerEntitlement?) {
        val wallet = bareWallet()
        val m = SirosWallet::class.declaredMemberFunctions.first { it.name == "enforceIssuerEntitlement" }
        m.isAccessible = true
        try {
            m.call(wallet, issuer, entitlement)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause ?: e
        }
    }

    /**
     * A SirosWallet with no fields set at all. enforceIssuerEntitlement and
     * issuerEntitlementFor must not depend on wallet state, so allocating
     * without running any initializer is the point rather than a shortcut.
     */
    private fun bareWallet(): SirosWallet {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe")
        unsafeField.isAccessible = true
        val allocate = unsafeClass.getMethod("allocateInstance", Class::class.java)
        return allocate.invoke(unsafeField.get(null), SirosWallet::class.java) as SirosWallet
    }
}
