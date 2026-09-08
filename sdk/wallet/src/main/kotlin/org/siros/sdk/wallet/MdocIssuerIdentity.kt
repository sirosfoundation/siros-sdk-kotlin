package org.siros.sdk.wallet

import java.net.URI
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The identity an mdoc issuer is known by, read from its document signer
 * (DS) certificate.
 *
 * Trust registries for mdoc issuers are keyed on the issuer's URL, not on
 * its certificate: go-trust's `mdociaca` registry takes `subject.id` as the
 * issuer URL, checks it against its allowlist, fetches that issuer's IACAs
 * from its published `mdoc_iacas_uri` and only then path-validates the
 * chain. Handing it a certificate hash as the subject can never match, and
 * the wallet's issuer-trust check then answered "not trusted" on every
 * deployment without a VICAL registry - which is every deployment today.
 *
 * Derived the same way the verifier side (vc's `extractMDocIssuerID`)
 * derives it, so both ends ask the registry about the same subject:
 *  1. the first URI SAN with an `https` scheme, or an `http` one lifted to
 *     `https` (metadata discovery is https-only);
 *  2. else the first non-wildcard DNS SAN, as `https://<host>`;
 *  3. else nothing - the caller falls back to identifying the certificate
 *     itself.
 *
 * The Organization fallback vc also has is deliberately not ported: it only
 * serves static allowlists of organisation names, which nothing the wallet
 * talks to uses, and an `O=` value looks nothing like a URL to a registry
 * that expects one.
 */
object MdocIssuerIdentity {

    private const val SAN_TYPE_DNS = 2
    private const val SAN_TYPE_URI = 6

    /**
     * The issuer URL named by [certificate]'s subject alternative names, or
     * null if it names none.
     */
    fun fromCertificate(certificate: X509Certificate): String? {
        val sans = try {
            certificate.subjectAlternativeNames ?: return null
        } catch (e: java.security.cert.CertificateParsingException) {
            return null
        }
        val uris = mutableListOf<String>()
        val dnsNames = mutableListOf<String>()
        for (entry in sans) {
            val type = entry.getOrNull(0) as? Int ?: continue
            val value = entry.getOrNull(1) as? String ?: continue
            when (type) {
                SAN_TYPE_URI -> uris += value
                SAN_TYPE_DNS -> dnsNames += value
            }
        }
        for (raw in uris) {
            val uri = runCatching { URI(raw) }.getOrNull() ?: continue
            when (uri.scheme?.lowercase()) {
                "https" -> return raw
                "http" -> return "https" + raw.substring(uri.scheme.length)
            }
        }
        return dnsNames.firstOrNull { !it.startsWith("*.") }?.let { "https://$it" }
    }

    /** [fromCertificate] for a DER-encoded certificate; null if it does not parse. */
    fun fromDer(der: ByteArray): String? {
        val certificate = runCatching {
            CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
        }.getOrNull() ?: return null
        return fromCertificate(certificate)
    }
}
