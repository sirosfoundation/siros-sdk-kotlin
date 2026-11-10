// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.wallet

import org.siros.sdk.transport.wmp.WmpEngineAskHandler

/**
 * One engine the wallet can run its WMP flows on - a member of the
 * user-configured prioritized list ([WalletConfig.engineProviders]).
 *
 * The wallet connects the FIRST provider that answers a connect: each in
 * priority order, each retried ([WalletConfig.engineConnectRetries])
 * before failing over to the next. Failover is a CONNECT-time behavior
 * only - a connected session is pinned to its provider for its life
 * (the mode-switching invariant: never mid-flow).
 */
sealed interface WmpEngineProvider {
    /**
     * A remote engine over the WMP HTTP+SSE binding (siros-wallet-core
     * engine-server - POST /wmp, the reply riding GET /wmp/events).
     *
     * @param sendUrl the engine's POST /wmp endpoint.
     * @param sseUrl the engine's GET /wmp/events endpoint.
     * @param tenantTokens whether the deployment's engine runs
     *   tenant-bound (`ENGINE_PRINCIPAL_MODE=tenant`, engine-parity.md
     *   §8): the bearer this provider mints is then the AS's
     *   pseudonymous engine kind. Must match the deployment - see
     *   [WalletConfig.wmpTenantTokens]'s doc comment.
     */
    data class RemoteHttpSse(
        val sendUrl: String,
        val sseUrl: String,
        val tenantTokens: Boolean = false,
    ) : WmpEngineProvider {
        override val label: String = "remote ($sendUrl)"
    }

    /**
     * The LOCAL engine: siros-wallet-core's engine core in-process
     * (the AAR's `WmpUniFFITransport` over the UniFFI ports), the
     * app's own transport constructed per connect from
     * [WmpEngineAskContext].
     */
    class Local(
        val transportFactory: suspend (WmpEngineAskContext) -> org.siros.sdk.transport.Transport,
    ) : WmpEngineProvider {
        override val label: String = "local (in-process)"
        override fun toString(): String = label

        // Identity semantics, deliberately: the factory is a function, and
        // two syntactically identical factories are not the same provider.
        // The type test is the contract's shape (a foreign object is never
        // equal, symmetric with the other side's own rule).
        override fun equals(other: Any?): Boolean = other is Local && this === other
        override fun hashCode(): Int = System.identityHashCode(this)
    }

    /** The user-facing name of the provider (logs, failover errors). */
    val label: String
}

/**
 * What the wallet hands a [WmpEngineProvider.Local] factory per connect
 * attempt - the pieces the in-process engine needs that are the wallet's
 * to provide.
 *
 * @property asks the wallet's ask handler - the same handlers answer the
 *   local engine's Host-port asks as answer the remote engine's child
 *   flows.
 * @property bearerProvider a FRESH wallet-backend bearer (cached until
 *   expired by the wallet's own token manager) - for the app's trust
 *   stack: a local [WmpEngineProvider.Local] engine evaluates issuer
 *   trust through the app-supplied `Pdp`, and the backend proxy's
 *   `/v1/evaluate` route is TAC-gated (a `wallet-backend`-audience token
 *   with `tac` covering `r` passes - exactly this bearer).
 */
class WmpEngineAskContext(
    val asks: WmpEngineAskHandler,
    val bearerProvider: suspend () -> String?,
)