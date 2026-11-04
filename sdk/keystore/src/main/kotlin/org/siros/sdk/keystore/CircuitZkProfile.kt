// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

/**
 * One credential/circuit profile that can be added to the standard catalog prover and presenter.
 *
 * The adapter owns the catalog `(system, systemVersion)` routing and proof invocation. The handlers
 * describe the profile's functions to the shared presenter: witness requirements, credential checks,
 * verifier identity, structured consent items and the explicit response result kind. Missing consent or
 * result metadata refuses rather than bypassing either check. A profile is eligible only when all of its pieces support the
 * request; registering an adapter never makes an unknown function valid or bypasses consent.
 *
 * This is the profile extension point, not a replacement proof-system registry. Alternative proof
 * systems such as Longfellow and Vega are composed through
 * [org.siros.sdk.credentials.ZkProofSystemRegistry] and [ZkMdocPresentation.standard]. The built-in nym_auth
 * and legacy mdoc profiles remain registered;
 * additional profiles are appended and every claim must be unique.
 */
data class CircuitZkProfile(
    val adapter: CircuitZkSystemAdapter,
    val handlers: List<CircuitZkFunctionHandler> = emptyList(),
) {
    companion object {
        /**
         * Every [profiles]' handlers, rejecting duplicate function ids instead of allowing a later
         * profile to shadow a built-in or another profile silently. The built-in nym_auth and legacy
         * profiles are supplied through this same registration path by [CatalogCircuitZkProver.standard].
         */
        fun handlers(profiles: List<CircuitZkProfile>): List<CircuitZkFunctionHandler> {
            val result = profiles.flatMap { it.handlers }
            require(result.map { it.functionId }.toSet().size == result.size) {
                "circuit_zk function id is claimed by two profiles"
            }
            return result
        }

        /** Validate additional registrations against the built-ins and configured predicates, without constructing native state. */
        fun validateAdditional(
            profiles: List<CircuitZkProfile>,
            predicates: org.siros.sdk.credentials.PredicateFunctions,
        ) {
            val keys = profiles.flatMap { it.adapter.systems }
            require(keys.size == keys.toSet().size && keys.none { it in NymAuthCircuitZkAdapter.SYSTEMS || it in LegacyZkCircuitZkAdapter.SYSTEMS }) {
                "circuit_zk system and version are claimed by two profiles"
            }
            val allHandlers = PredicateFunctionHandler.handlersFor(predicates) + profiles.flatMap { it.handlers }
            require(allHandlers.map { it.functionId }.toSet().size == allHandlers.size) {
                "circuit_zk function id is claimed by two profiles"
            }
        }
    }
}
