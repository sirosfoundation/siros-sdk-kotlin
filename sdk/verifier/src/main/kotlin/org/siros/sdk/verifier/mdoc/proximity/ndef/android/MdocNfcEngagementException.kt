// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef.android

/** Failures specific to reading an ISO 18013-5 static handover from an NFC Type 4 Tag. */
sealed class MdocNfcEngagementException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The device has no default NFC adapter. */
    class NfcUnavailable internal constructor(cause: Throwable? = null) :
        MdocNfcEngagementException("NFC is unavailable on this device", cause)

    /** NFC is present but switched off. */
    class NfcDisabled internal constructor() : MdocNfcEngagementException("NFC is disabled")

    /** Another [MdocNfcEngagementReader.read] is still outstanding on this reader. */
    class ReadInProgress internal constructor() : MdocNfcEngagementException("An NFC engagement read is already in progress")

    /** No tag was discovered while reader mode was armed, or the discovered tag is not ISO-DEP. */
    class NoTag internal constructor(message: String) : MdocNfcEngagementException(message)

    /** The overall read deadline expired after reader mode was enabled or a tag was discovered. */
    class Timeout internal constructor(val timeoutMillis: Long) :
        MdocNfcEngagementException("NFC engagement read timed out after $timeoutMillis ms")

    /** The NDEF length cannot be read within the parser and Type 4 READ BINARY bounds. */
    class InvalidNdef internal constructor(message: String) : MdocNfcEngagementException(message)

    /** An ISO-DEP exchange failed or returned a malformed/truncated response. */
    class ApduFailure internal constructor(
        val operation: String,
        message: String,
        cause: Throwable? = null,
    ) : MdocNfcEngagementException(message, cause)

    /** A Type 4 command returned a status word other than exact `9000`. */
    class ApduStatus internal constructor(
        val operation: String,
        val statusWord: Int,
    ) : MdocNfcEngagementException(
        "$operation failed with SW=${statusWord.toString(16).uppercase().padStart(4, '0')}",
    )
}
