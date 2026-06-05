// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * Configuration for [SirosWallet].
 *
 * @param backendUrl The wallet backend URL (e.g. "https://wallet.sirosid.dev").
 * @param tenantId  Tenant identifier. Defaults to "default".
 */
data class WalletConfig(
    val backendUrl: String,
    val tenantId: String = "default",
)
