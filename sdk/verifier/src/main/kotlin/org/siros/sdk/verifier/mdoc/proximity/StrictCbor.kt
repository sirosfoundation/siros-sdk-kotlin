// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** A small strict CBOR reader which retains source spans and semantic map keys. */
internal sealed interface CborValue {
    val start: Int
    val end: Int

    data class Integer(val value: BigInteger, override val start: Int, override val end: Int) : CborValue
    class Bytes(val value: ByteArray, override val start: Int, override val end: Int) : CborValue
    data class Text(val value: String, override val start: Int, override val end: Int) : CborValue
    data class Array(val items: List<CborValue>, override val start: Int, override val end: Int) : CborValue
    data class Map(val entries: List<Entry>, override val start: Int, override val end: Int) : CborValue {
        data class Entry(val key: CborValue, val value: CborValue)
    }
    data class Tag(val tag: BigInteger, val item: CborValue, override val start: Int, override val end: Int) : CborValue
    data class Boolean(val value: kotlin.Boolean, override val start: Int, override val end: Int) : CborValue
    class Other(val raw: ByteArray, override val start: Int, override val end: Int) : CborValue
}

internal class CborDecodeException(message: String) : Exception(message)

internal object StrictCbor {
    private const val MAX_DEPTH = 16

    /** Decodes exactly one definite-length item and rejects duplicate map keys. */
    fun decode(bytes: ByteArray): CborValue {
        val reader = Reader(bytes)
        val value = reader.item(0)
        if (reader.position != bytes.size) throw CborDecodeException("trailing CBOR bytes")
        return value
    }

    private class Reader(private val bytes: ByteArray) {
        var position = 0
            private set

        private fun remaining(): Int = bytes.size - position

        private fun take(count: Int): ByteArray {
            if (count < 0 || count > remaining()) throw CborDecodeException("truncated CBOR")
            return bytes.copyOfRange(position, position + count).also { position += count }
        }

        private fun argument(info: Int): BigInteger = when (info) {
            in 0..23 -> BigInteger.valueOf(info.toLong())
            24 -> BigInteger(1, take(1))
            25 -> BigInteger(1, take(2))
            26 -> BigInteger(1, take(4))
            27 -> BigInteger(1, take(8))
            else -> throw CborDecodeException("invalid CBOR additional information")
        }

        private fun length(argument: BigInteger): Int {
            if (argument > BigInteger.valueOf(Int.MAX_VALUE.toLong())) {
                throw CborDecodeException("CBOR length is too large")
            }
            return argument.toInt()
        }

        fun item(depth: Int): CborValue {
            if (depth > MAX_DEPTH) throw CborDecodeException("CBOR nesting is too deep")
            val start = position
            val initial = take(1)[0].toInt() and 0xff
            val major = initial shr 5
            val info = initial and 0x1f

            if (major == 7) return simple(start, initial, info)
            if (info == 31) throw CborDecodeException("indefinite-length CBOR is not supported")

            val argument = argument(info)
            val value = when (major) {
                0 -> CborValue.Integer(argument, start, 0)
                1 -> CborValue.Integer(argument.negate().subtract(BigInteger.ONE), start, 0)
                2 -> CborValue.Bytes(take(length(argument)), start, 0)
                3 -> CborValue.Text(text(take(length(argument))), start, 0)
                4 -> array(length(argument), depth, start)
                5 -> map(length(argument), depth, start)
                6 -> CborValue.Tag(argument, item(depth + 1), start, 0)
                else -> throw CborDecodeException("unsupported CBOR major type")
            }
            return withEnd(value)
        }

        private fun simple(start: Int, initial: Int, info: Int): CborValue {
            val value = when (info) {
                20 -> CborValue.Boolean(false, start, 0)
                21 -> CborValue.Boolean(true, start, 0)
                24 -> CborValue.Other(byteArrayOf(initial.toByte()) + take(1), start, 0)
                25 -> CborValue.Other(byteArrayOf(initial.toByte()) + take(2), start, 0)
                26 -> CborValue.Other(byteArrayOf(initial.toByte()) + take(4), start, 0)
                27 -> CborValue.Other(byteArrayOf(initial.toByte()) + take(8), start, 0)
                in 28..31 -> throw CborDecodeException("invalid CBOR simple value")
                else -> CborValue.Other(byteArrayOf(initial.toByte()), start, 0)
            }
            return withEnd(value)
        }

        private fun array(length: Int, depth: Int, start: Int): CborValue {
            if (length > remaining()) throw CborDecodeException("truncated CBOR array")
            return CborValue.Array(List(length) { item(depth + 1) }, start, 0)
        }

        private fun map(length: Int, depth: Int, start: Int): CborValue {
            if (length > remaining() / 2) throw CborDecodeException("truncated CBOR map")
            val entries = ArrayList<CborValue.Map.Entry>(length)
            repeat(length) {
                val key = item(depth + 1)
                val value = item(depth + 1)
                if (entries.any { sameSemanticValue(it.key, key) }) {
                    throw CborDecodeException("duplicate CBOR map key")
                }
                entries.add(CborValue.Map.Entry(key, value))
            }
            return CborValue.Map(entries, start, 0)
        }

        private fun withEnd(value: CborValue): CborValue {
            val end = position
            return when (value) {
                is CborValue.Integer -> value.copy(end = end)
                is CborValue.Bytes -> CborValue.Bytes(value.value, value.start, end)
                is CborValue.Text -> value.copy(end = end)
                is CborValue.Array -> value.copy(end = end)
                is CborValue.Map -> value.copy(end = end)
                is CborValue.Tag -> value.copy(end = end)
                is CborValue.Boolean -> value.copy(end = end)
                is CborValue.Other -> CborValue.Other(value.raw, value.start, end)
            }
        }

        private fun text(bytes: ByteArray): String {
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            return try {
                decoder.decode(ByteBuffer.wrap(bytes)).toString()
            } catch (e: CharacterCodingException) {
                throw CborDecodeException("invalid UTF-8 in CBOR text string")
            }
        }
    }
}

private fun sameSemanticValue(first: CborValue, second: CborValue): Boolean = when (first) {
    is CborValue.Integer -> second is CborValue.Integer && first.value == second.value
    is CborValue.Bytes -> second is CborValue.Bytes && first.value.contentEquals(second.value)
    is CborValue.Text -> second is CborValue.Text && first.value == second.value
    is CborValue.Array -> second is CborValue.Array &&
        first.items.size == second.items.size &&
        first.items.zip(second.items).all { (a, b) -> sameSemanticValue(a, b) }
    is CborValue.Map -> second is CborValue.Map &&
        first.entries.size == second.entries.size &&
        first.entries.zip(second.entries).all { (a, b) ->
            sameSemanticValue(a.key, b.key) && sameSemanticValue(a.value, b.value)
        }
    is CborValue.Tag -> second is CborValue.Tag && first.tag == second.tag && sameSemanticValue(first.item, second.item)
    is CborValue.Boolean -> second is CborValue.Boolean && first.value == second.value
    is CborValue.Other -> second is CborValue.Other && first.raw.contentEquals(second.raw)
}
