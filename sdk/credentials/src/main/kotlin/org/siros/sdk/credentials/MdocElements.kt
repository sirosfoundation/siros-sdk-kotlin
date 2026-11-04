// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import org.siros.sdk.credentials.mdoc.DocumentMdoc

/** Strict mdoc element lookup shared by credential profiles. */
object MdocElements {
    /**
     * The value of [name] in [namespace], or null when the namespace or element is absent or the
     * element occurs more than once. No other namespace is consulted and a decoy value cannot be
     * substituted for the requested one.
     */
    fun single(document: DocumentMdoc, namespace: String, name: String): CBORObject? {
        val matches = document.issuerSigned.nameSpaces[namespace].orEmpty().filter { it.item.elementIdentifier == name }
        return matches.singleOrNull()?.item?.elementValue
    }
}
