// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import java.math.BigDecimal
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.mdoc.DocumentMdoc

/** The type of the claim a predicate function tests (and so of its operands). */
enum class ValueType(val wire: String) {
    DATE("date"), NUMBER("number"), STRING("string"), BOOL("bool");

    companion object {
        fun ofWire(w: String): ValueType? = values().firstOrNull { it.wire == w }
    }
}

/** A comparison a predicate function can make. Ordering comparisons apply to dates and numbers only. */
enum class ComparisonOp(val wire: String, val ordering: Boolean) {
    EQ("eq", false), NE("ne", false), LT("lt", true), LE("le", true), GT("gt", true), GE("ge", true), IN("in", false);

    companion object {
        fun ofWire(w: String): ComparisonOp? = values().firstOrNull { it.wire == w }
    }
}

/** One comparison of a predicate: [op] against [values] (one operand, or the set of an `in`), as text of the claim's type. */
data class Condition(val op: ComparisonOp, val values: List<String>)

/** The claim a predicate is about: its [path] and the credential's OWN display label for it (never invented), if it has one. */
data class ClaimRef(val path: List<String>, val label: String?) {
    /** The label, else the path. */
    val display: String get() = label ?: path.joinToString(".")
}

/** A claim value read from a credential, as text of [type]. */
data class ClaimValue(val type: ValueType, val text: String)

/** What a credential holds at a claim path. */
sealed interface ClaimLookup {
    /** The claim is not in the credential: a predicate over it cannot hold. */
    object Absent : ClaimLookup

    /** The claim is there. */
    data class Found(val value: ClaimValue) : ClaimLookup

    /** This reader cannot read that path or format: the pre-check is skipped, never guessed. */
    object Unsupported : ClaimLookup
}

/** Where a predicate function takes its claim from. */
sealed interface ClaimSource {
    /** Always the same claim (`age_check` is about `birth_date`). */
    data class Fixed(val path: List<String>) : ClaimSource

    /** The function's `claim` parameter: a string (one path element) or an array of strings. */
    object FromParam : ClaimSource
}

/**
 * The declaration of one predicate function: what it tests, so that consent, the local pre-check and the
 * cross-query rule can be driven by data. The set of `circuit_zk` functions is open-ended; adding one is
 * declaring it here (and registering its validator rules and prover).
 *
 * A function's params are a CONJUNCTION of comparisons on one claim: each param named in [comparisons] is one
 * [Condition] (`ge` + `le` is a range). Any other param refuses the request.
 *
 * @property comparisons param name to comparison, in display order.
 * @property minSpan The function's declared minimum selectivity, or null if it declares none (then no merge rule
 *   applies to it). For a date claim: calendar days, inclusive (`le - ge + 1`); for a number: `le - ge`. Needs
 *   `ge` and `le` only.
 * @property ageSpecialisation Renders as an age (born between / at least / at most). Needs a date claim and `ge`/`le` only.
 */
class PredicateFunction(
    val id: String,
    val claim: ClaimSource,
    val valueType: ValueType,
    val comparisons: Map<String, ComparisonOp>,
    val minSpan: Long? = null,
    val ageSpecialisation: Boolean = false,
) {
    init {
        require(comparisons.isNotEmpty()) { "$id declares no comparison" }
        for (op in comparisons.values) {
            require(!op.ordering || valueType == ValueType.DATE || valueType == ValueType.NUMBER) { "$id: ${op.wire} on ${valueType.wire}" }
        }
        val ge = comparisons.filterValues { it == ComparisonOp.GE }.keys
        val le = comparisons.filterValues { it == ComparisonOp.LE }.keys
        if (minSpan != null || ageSpecialisation) {
            require(comparisons.size == 2 && ge.size == 1 && le.size == 1) { "$id: a span or age rendering needs exactly ge and le" }
            require(valueType == ValueType.DATE || (valueType == ValueType.NUMBER && minSpan != null && !ageSpecialisation)) { "$id: unsupported span/age type" }
        }
        if (ageSpecialisation) require(valueType == ValueType.DATE) { "$id: age rendering needs a date claim" }
        require(minSpan == null || minSpan >= 0) { "$id: negative minSpan" }
    }

    private val geParam get() = comparisons.entries.first { it.value == ComparisonOp.GE }.key
    private val leParam get() = comparisons.entries.first { it.value == ComparisonOp.LE }.key

    /** A function item read through this declaration. */
    class Parsed(val claimPath: List<String>, val conditions: List<Condition>)

    /** The claim path and conditions of [fn], or null when its params are not exactly what this declaration allows. */
    fun parse(fn: CircuitZkFunction): Parsed? {
        if (fn.id != id) return null
        val path = when (claim) {
            is ClaimSource.Fixed -> claim.path
            ClaimSource.FromParam -> claimParam(fn.params["claim"] ?: return null) ?: return null
        }
        val allowed = comparisons.keys + (if (claim == ClaimSource.FromParam) setOf("claim") else emptySet())
        if (fn.params.keys.any { it !in allowed }) return null
        val conditions = comparisons.mapNotNull { (param, op) ->
            val raw = fn.params[param] ?: return@mapNotNull null
            val values = if (op == ComparisonOp.IN) {
                val a = (raw as? JsonArray)?.map { operand(it) ?: return null } ?: return null
                if (a.isEmpty() || a.toSet().size != a.size) return null
                a
            } else {
                listOf(operand(raw) ?: return null)
            }
            Condition(op, values)
        }
        if (conditions.isEmpty()) return null
        return Parsed(path, conditions)
    }

    private fun claimParam(e: JsonElement): List<String>? = when (e) {
        is JsonPrimitive -> if (e.isString && e.content.isNotEmpty()) listOf(e.content) else null
        is JsonArray -> e.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString && p.content.isNotEmpty() }?.content ?: return null }
            .takeIf { it.isNotEmpty() }
        else -> null
    }

    /** One operand as text of [valueType], or null when it is not a well-formed one. */
    private fun operand(e: JsonElement): String? {
        val p = e as? JsonPrimitive ?: return null
        return when (valueType) {
            ValueType.DATE -> p.content.takeIf { p.isString && PredicateFunctions.date(it) != null }
            ValueType.NUMBER -> p.content.takeIf { !p.isString && PredicateFunctions.number(it) != null }
            ValueType.STRING -> p.content.takeIf { p.isString }
            ValueType.BOOL -> p.content.takeIf { !p.isString && (it == "true" || it == "false") }
        }
    }

    /** The age of a `ge`/`le` date predicate, for an [ageSpecialisation]. */
    internal fun ageForm(conditions: List<Condition>, today: LocalDate): AgeForm? {
        if (!ageSpecialisation) return null
        val ge = conditions.firstOrNull { it.op == ComparisonOp.GE }?.values?.single()
        val le = conditions.firstOrNull { it.op == ComparisonOp.LE }?.values?.single()
        val gd = PredicateFunctions.date(ge)
        val ld = PredicateFunctions.date(le)
        // Born on `le` is the youngest holder the range admits, born on `ge` the oldest.
        fun years(born: LocalDate) = ChronoUnit.YEARS.between(born, today).toInt().coerceAtLeast(0)
        return when {
            gd != null && ld != null -> AgeForm.Between(ge!!, le!!, years(ld), years(gd))
            ld != null -> AgeForm.AtLeast(years(ld))
            gd != null -> AgeForm.AtMost(years(gd))
            else -> null
        }
    }

    /** The `ge` and `le` operands of [conditions] (for the span rule), or null. */
    internal fun bounds(conditions: List<Condition>): Pair<String?, String?> =
        conditions.firstOrNull { it.op == ComparisonOp.GE }?.values?.single() to conditions.firstOrNull { it.op == ComparisonOp.LE }?.values?.single()

    internal val geName get() = geParam
    internal val leName get() = leParam
}

/**
 * The registry of predicate functions the wallet can describe, pre-check and merge-check. A function in a
 * plan that is not declared here (and is not a pseudonym or the legacy disclosure) cannot be described to the
 * user, so the request is refused before consent.
 */
class PredicateFunctions(functions: List<PredicateFunction>) {
    private val byId: Map<String, PredicateFunction> = functions.associateBy { it.id }.also {
        require(it.size == functions.size) { "duplicate predicate function id" }
    }

    operator fun get(id: String): PredicateFunction? = byId[id]

    /** The consent item for [fn], or null (undeclared function, or params the declaration does not allow). */
    fun item(fn: CircuitZkFunction, claims: List<ClaimMeta>, today: LocalDate): ConsentItem.Predicate? {
        val f = byId[fn.id] ?: return null
        val parsed = f.parse(fn) ?: return null
        val label = claims.firstOrNull { it.path == parsed.claimPath }?.label?.takeIf { it.isNotBlank() }
        return ConsentItem.Predicate(fn.id, ClaimRef(parsed.claimPath, label), f.valueType, parsed.conditions, f.ageForm(parsed.conditions, today))
    }

    /**
     * The local satisfiability pre-check of [plan] against what [reader] finds in the credential: false when a
     * predicate definitely does not hold (claim absent, wrong type, or the comparison is false); true when it holds
     * OR cannot be judged (a path or format the reader does not support): the pre-check never guesses. It is only a
     * convenience so the user is not asked to consent to something that will be refused; the prover decides.
     */
    fun precheck(plan: CircuitZkPlan, reader: (path: List<String>, type: ValueType) -> ClaimLookup): Boolean {
        for (fn in plan.functions) {
            val f = byId[fn.id] ?: continue
            val parsed = f.parse(fn) ?: return false
            when (val found = reader(parsed.claimPath, f.valueType)) {
                ClaimLookup.Absent -> return false
                ClaimLookup.Unsupported -> continue
                is ClaimLookup.Found -> if (!holds(f.valueType, parsed.conditions, found.value)) return false
            }
        }
        return true
    }

    /**
     * The cross-query rule: the proofs of one request together reveal the INTERSECTION of the predicates on a
     * claim. For plans answered with the SAME credential, per claim path: the `ge` bounds are intersected (max),
     * the `le` bounds (min), and where a function involved DECLARES a minimum selectivity ([PredicateFunction.minSpan])
     * the strictest declared minimum must still hold (`age_check`: at least 365 days). Functions that declare none
     * have no merge rule. An unreadable bound is false, never "cannot compare, so fine".
     */
    fun mergeRuleOk(plans: List<CircuitZkPlan>): Boolean {
        class Acc(var lower: String? = null, var upper: String? = null, var min: Long = 0, var type: ValueType = ValueType.DATE)
        val groups = LinkedHashMap<List<String>, Acc>()
        for (fn in plans.flatMap { it.functions }) {
            val f = byId[fn.id] ?: continue
            val min = f.minSpan ?: continue
            val parsed = f.parse(fn) ?: return false
            val (ge, le) = f.bounds(parsed.conditions)
            val acc = groups.getOrPut(parsed.claimPath) { Acc(type = f.valueType) }
            if (acc.type != f.valueType) return false
            acc.min = maxOf(acc.min, min)
            if (ge != null && (acc.lower == null || compare(f.valueType, ge, acc.lower!!) > 0)) acc.lower = ge
            if (le != null && (acc.upper == null || compare(f.valueType, le, acc.upper!!) < 0)) acc.upper = le
        }
        for (acc in groups.values) {
            val lo = acc.lower ?: continue
            val hi = acc.upper ?: continue
            val span = when (acc.type) {
                ValueType.DATE -> ChronoUnit.DAYS.between(date(lo), date(hi)) + 1
                else -> number(hi)!!.subtract(number(lo)!!).toLong()
            }
            if (span < acc.min) return false
        }
        return true
    }

    companion object {
        /** `age_check` of the rulebook: `birth_date` within `ge`..`le`, at least 365 days wide, shown as an age. */
        val AGE_CHECK = PredicateFunction(
            id = CircuitZkRuleSet.AGE_CHECK,
            claim = ClaimSource.Fixed(listOf("birth_date")),
            valueType = ValueType.DATE,
            comparisons = linkedMapOf("ge" to ComparisonOp.GE, "le" to ComparisonOp.LE),
            minSpan = 365,
            ageSpecialisation = true,
        )

        /** The rulebook's functions: `age_check`. */
        val DEFAULT = PredicateFunctions(listOf(AGE_CHECK))

        private val FULL_DATE = Regex("\\d{4}-\\d{2}-\\d{2}")
        private val NUMBER = Regex("-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?")

        /** A strict RFC 3339 full-date (`YYYY-MM-DD`), or null. */
        fun date(s: String?): LocalDate? =
            s?.takeIf { FULL_DATE.matches(it) }?.let { try { LocalDate.parse(it) } catch (e: DateTimeParseException) { null } }

        /** A JSON number literal, or null. */
        fun number(s: String?): BigDecimal? = s?.takeIf { NUMBER.matches(it) }?.let { try { BigDecimal(it) } catch (e: NumberFormatException) { null } }

        private fun compare(type: ValueType, a: String, b: String): Int = when (type) {
            ValueType.DATE -> date(a)!!.compareTo(date(b)!!)
            ValueType.NUMBER -> number(a)!!.compareTo(number(b)!!)
            else -> a.compareTo(b)
        }

        /** Whether [value] satisfies every [conditions]. A value of another type does not. Pure; shared with the vectors. */
        fun holds(type: ValueType, conditions: List<Condition>, value: ClaimValue): Boolean {
            if (value.type != type) return false
            return conditions.all { c ->
                when (c.op) {
                    ComparisonOp.EQ -> same(type, value.text, c.values[0])
                    ComparisonOp.NE -> !same(type, value.text, c.values[0])
                    ComparisonOp.IN -> c.values.any { same(type, value.text, it) }
                    ComparisonOp.LT -> compare(type, value.text, c.values[0]) < 0
                    ComparisonOp.LE -> compare(type, value.text, c.values[0]) <= 0
                    ComparisonOp.GT -> compare(type, value.text, c.values[0]) > 0
                    ComparisonOp.GE -> compare(type, value.text, c.values[0]) >= 0
                }
            }
        }

        private fun same(type: ValueType, a: String, b: String) = if (type == ValueType.STRING || type == ValueType.BOOL) a == b else compare(type, a, b) == 0

        /**
         * A claim reader over an mdoc: only a one-element path in the credential's own doctype namespace (the
         * namespace nym_auth binds) is read; anything else is [ClaimLookup.Unsupported]. A duplicated element is
         * absent; a value of another CBOR type than [ValueType] is a [ClaimLookup.Found] of a mismatching type
         * (so no comparison holds).
         */
        fun mdocReader(document: DocumentMdoc): (List<String>, ValueType) -> ClaimLookup = { path, type ->
            if (path.size != 1) {
                ClaimLookup.Unsupported
            } else {
                val v = SecretSeedCommitment.doctypeElement(document, path[0])
                if (v == null) ClaimLookup.Absent else ClaimLookup.Found(read(v, type))
            }
        }

        private fun read(v0: CBORObject, type: ValueType): ClaimValue {
            val v = if (v0.isTagged) v0.UntagOne() else v0
            val mismatch = ClaimValue(if (type == ValueType.STRING) ValueType.BOOL else ValueType.STRING, "")
            return when (type) {
                ValueType.DATE -> if (v.type == CBORType.TextString && date(v.AsString()) != null) ClaimValue(type, v.AsString()) else mismatch
                ValueType.STRING -> if (v.type == CBORType.TextString) ClaimValue(type, v.AsString()) else mismatch
                ValueType.BOOL -> if (v.type == CBORType.Boolean) ClaimValue(type, v.isTrue.toString()) else mismatch
                ValueType.NUMBER -> when (v.type) {
                    CBORType.Integer -> ClaimValue(type, v.AsNumber().ToEInteger().toString())
                    CBORType.FloatingPoint -> v.AsDoubleValue().takeIf { it.isFinite() }?.let { ClaimValue(type, BigDecimal.valueOf(it).toPlainString()) } ?: mismatch
                    else -> mismatch
                }
            }
        }
    }
}
