package at.daho.cypherrewriting.verification

import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparserImpl
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import kotlin.random.Random

class FuzzQueryMutationTest {

    private val schema = CypherSchema {
        val user = cypherNode("User") {
            property("id", Long::class, 100L, 200L, 300L)
            property("name", String::class, "Alice", "Bob", "Charlie")
        }
        val review = cypherNode("Review") {
            property("id", Long::class, 10L, 20L, 30L)
        }
        cypherRelationship(user, "WROTE", review)
    }

    private val unparser = CypherRewritingUnparserImpl()

    private val operatorPattern = Regex("""WHERE .+?\s(<=|>=|<>|<|>|=|STARTS WITH|ENDS WITH|CONTAINS|IS NOT NULL|IS NULL)\s""")

    private val expectedFlips = mapOf(
        "=" to "<>",
        "<>" to "=",
        "<" to ">=",
        ">=" to "<",
        ">" to "<=",
        "<=" to ">",
        "STARTS WITH" to "<>",
        "ENDS WITH" to "<>",
        "CONTAINS" to "<>",
        "IS NULL" to "IS NOT NULL",
        "IS NOT NULL" to "IS NULL"
    )

    private fun buildSettings(seed: Long, nullCheckProbability: Double = 0.0): FuzzSettings {
        return FuzzSettings(
            pattern = PatternSettings(patternsPerQuery = 1..1, length = 2..2, variableProbability = 1.0),
            node = NodeSettings(
                variableProbability = 1.0,
                labelsPerNode = 1..1,
                propertiesPerNode = 0..0,
                defectLabelProbability = 0.0
            ),
            relationship = RelationshipSettings(defectDirectionProbability = 0.0, defectConnectionProbability = 0.0, defectTypeProbability = 0.0, defectLabelProbability = 0.0),
            where = WhereSettings(probability = 1.0, length = 1..1, nullCheckProbability = nullCheckProbability),
            returnSettings = ReturnSettings(
                length = 1..1,
                asteriskProbability = 0.0,
                propertyAccessProbability = 0.0,
                aggregationProbability = 0.0,
                limitProbability = 0.0,
                skipProbability = 0.0,
                distinctProbability = 0.0,
                orderBy = OrderBySettings(probability = 0.0)
            ),
            random = Random(seed)
        )
    }

    private fun extractOperator(query: String): String? {
        return operatorPattern.find(query)?.groupValues?.get(1)
    }

    @Test
    fun mutateFlipsComparisonOperators() {
        val observedFlips = mutableMapOf<String, String>()

        for (seed in 0L..1000L) {
            val settings = buildSettings(seed, nullCheckProbability = 0.0)
            val fuzzQuery = FuzzQuery(schema, settings)
            val (ast, _) = fuzzQuery.generateWithMetrics()
            val originalQuery = unparser.render(ast)

            val mutated = fuzzQuery.mutateIndirectWhereValues()
            if (!mutated) continue

            val mutatedQuery = unparser.render(ast)
            val originalOp = extractOperator(originalQuery) ?: continue
            val mutatedOp = extractOperator(mutatedQuery) ?: continue

            assertEquals(
                expectedFlips[originalOp], mutatedOp,
                "Seed $seed: '$originalOp' should flip to '${expectedFlips[originalOp]}', but got '$mutatedOp'.\n" +
                        "  Original: $originalQuery\n  Mutated:  $mutatedQuery"
            )
            observedFlips[originalOp] = mutatedOp
        }

        assertTrue(observedFlips.isNotEmpty(), "Should have found at least one mutation case across 1000 seeds")
    }

    @Test
    fun mutateFlipsNullCheckOperators() {
        val observedFlips = mutableMapOf<String, String>()

        for (seed in 0L..1000L) {
            val settings = buildSettings(seed, nullCheckProbability = 1.0)
            val fuzzQuery = FuzzQuery(schema, settings)
            val (ast, _) = fuzzQuery.generateWithMetrics()
            val originalQuery = unparser.render(ast)

            val mutated = fuzzQuery.mutateIndirectWhereValues()
            if (!mutated) continue

            val mutatedQuery = unparser.render(ast)
            val originalOp = extractOperator(originalQuery) ?: continue
            val mutatedOp = extractOperator(mutatedQuery) ?: continue

            assertEquals(
                expectedFlips[originalOp], mutatedOp,
                "Seed $seed: '$originalOp' should flip to '${expectedFlips[originalOp]}', but got '$mutatedOp'.\n" +
                        "  Original: $originalQuery\n  Mutated:  $mutatedQuery"
            )
            observedFlips[originalOp] = mutatedOp
        }

        assertTrue(observedFlips.containsKey("IS NULL") || observedFlips.containsKey("IS NOT NULL"),
            "Should have observed at least one IS NULL / IS NOT NULL flip")
    }

    @Test
    fun mutateReturnsFalseWhenNoIndirectVariables() {
        for (seed in 0L..100L) {
            val settings = FuzzSettings(
                pattern = PatternSettings(patternsPerQuery = 1..1, length = 1..1, variableProbability = 1.0),
                node = NodeSettings(
                    variableProbability = 1.0,
                    labelsPerNode = 1..1,
                    propertiesPerNode = 0..0,
                    defectLabelProbability = 0.0
                ),
                where = WhereSettings(probability = 1.0, length = 1..1, nullCheckProbability = 0.0),
                returnSettings = ReturnSettings(
                    length = 1..1,
                    asteriskProbability = 1.0,
                    propertyAccessProbability = 0.0,
                    aggregationProbability = 0.0,
                    limitProbability = 0.0,
                    skipProbability = 0.0,
                    distinctProbability = 0.0,
                    orderBy = OrderBySettings(probability = 0.0)
                ),
                random = Random(seed)
            )
            val fuzzQuery = FuzzQuery(schema, settings)
            fuzzQuery.generateWithMetrics()

            val mutated = fuzzQuery.mutateIndirectWhereValues()

            assertFalse(mutated, "Seed $seed: With RETURN *, all variables are returned so no indirect variables exist")
        }
    }

    @Test
    fun mutateDoesNotChangeReturnedQuery() {
        for (seed in 0L..200L) {
            val settings = buildSettings(seed)
            val fuzzQuery = FuzzQuery(schema, settings)
            val (ast, _) = fuzzQuery.generateWithMetrics()
            val originalQuery = unparser.render(ast)

            val mutated = fuzzQuery.mutateIndirectWhereValues()
            if (mutated) continue

            val queryAfterNoMutation = unparser.render(ast)
            assertEquals(originalQuery, queryAfterNoMutation,
                "Seed $seed: When mutation returns false, query should remain unchanged")
        }
    }

    @Test
    fun mutatedQueryDiffersFromOriginal() {
        var foundMutation = false
        for (seed in 0L..500L) {
            val settings = buildSettings(seed)
            val fuzzQuery = FuzzQuery(schema, settings)
            val (ast, _) = fuzzQuery.generateWithMetrics()
            val originalQuery = unparser.render(ast)

            val mutated = fuzzQuery.mutateIndirectWhereValues()
            if (!mutated) continue

            val mutatedQuery = unparser.render(ast)
            assertNotEquals(originalQuery, mutatedQuery,
                "Seed $seed: Mutated query must differ from original.\n  Query: $originalQuery")
            foundMutation = true
        }
        assertTrue(foundMutation, "Should have found at least one successful mutation")
    }

    @Test
    fun allowedLabelsRestrictsGeneratedNodes() {
        val threeNodeSchema = CypherSchema {
            val user = cypherNode("User") { property("id", Long::class, 1L, 2L) }
            val review = cypherNode("Review") { property("id", Long::class, 10L, 20L) }
            val host = cypherNode("Host") { property("id", Long::class, 100L, 200L) }
            cypherRelationship(user, "WROTE", review)
            cypherRelationship(host, "HOSTS", review)
        }

        for (seed in 0L..200L) {
            val settings = FuzzSettings(
                pattern = PatternSettings(patternsPerQuery = 1..1, length = 2..2, variableProbability = 1.0),
                node = NodeSettings(
                    variableProbability = 1.0,
                    labelsPerNode = 1..1,
                    propertiesPerNode = 0..0,
                    defectLabelProbability = 0.0,
                    allowedLabels = setOf("User", "Review")
                ),
                returnSettings = ReturnSettings(
                    length = 1..1, asteriskProbability = 0.0, propertyAccessProbability = 0.0,
                    aggregationProbability = 0.0, limitProbability = 0.0, skipProbability = 0.0,
                    distinctProbability = 0.0, orderBy = OrderBySettings(probability = 0.0)
                ),
                where = WhereSettings(probability = 0.0),
                random = Random(seed)
            )
            val fuzzQuery = FuzzQuery(threeNodeSchema, settings)
            val (ast, _) = fuzzQuery.generateWithMetrics()
            val query = unparser.render(ast)

            assertFalse(query.contains(":Host"), "Seed $seed: Host should not appear with allowedLabels={User,Review}.\n  Query: $query")
        }
    }

    @Test
    fun allowedLabelsNullAllowsAllNodes() {
        val threeNodeSchema = CypherSchema {
            val user = cypherNode("User") { property("id", Long::class, 1L) }
            val review = cypherNode("Review") { property("id", Long::class, 10L) }
            val host = cypherNode("Host") { property("id", Long::class, 100L) }
            cypherRelationship(user, "WROTE", review)
            cypherRelationship(host, "HOSTS", review)
        }

        val allLabels = mutableSetOf<String>()
        for (seed in 0L..500L) {
            val settings = FuzzSettings(
                pattern = PatternSettings(patternsPerQuery = 1..1, length = 2..2, variableProbability = 1.0),
                node = NodeSettings(
                    variableProbability = 1.0,
                    labelsPerNode = 1..1,
                    propertiesPerNode = 0..0,
                    defectLabelProbability = 0.0,
                    allowedLabels = null
                ),
                returnSettings = ReturnSettings(
                    length = 1..1, asteriskProbability = 0.0, propertyAccessProbability = 0.0,
                    aggregationProbability = 0.0, limitProbability = 0.0, skipProbability = 0.0,
                    distinctProbability = 0.0, orderBy = OrderBySettings(probability = 0.0)
                ),
                where = WhereSettings(probability = 0.0),
                random = Random(seed)
            )
            val fuzzQuery = FuzzQuery(threeNodeSchema, settings)
            val (ast, _) = fuzzQuery.generateWithMetrics()
            val query = unparser.render(ast)

            for (label in listOf("User", "Review", "Host")) {
                if (query.contains(":$label")) allLabels.add(label)
            }
        }

        assertEquals(setOf("User", "Review", "Host"), allLabels,
            "With allowedLabels=null, all node types should eventually appear")
    }
}