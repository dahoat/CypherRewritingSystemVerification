package at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer

import at.daho.cypherrewriting.cypherverificatorairbnb.SessionBean
import at.daho.cypherrewriting.cypherverificatorairbnb.model.FuzzRunContext
import at.daho.cypherrewriting.verification.FuzzItem
import at.daho.cypherrewriting.verification.FuzzSettings
import at.daho.cypherrewriting.verification.fuzzSettings
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.PermissionDetector
import at.jku.faw.symspace.cypherrewriter.core.cypher.enforcer.CypherEnforcer
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import org.neo4j.driver.Session
import org.neo4j.driver.internal.types.InternalTypeSystem
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

private const val NON_EXISTENT_USER = "0"
private const val BULK_QUERY_USER_ID_FOR_REVIEW_ID = "MATCH (u:User)-[:WROTE]->(r:Review) RETURN u.id as userId, r.id as reviewId"

@Component
@Profile("review-ownership-fuzzer")
class ReviewOwnershipFuzzer(
    sessionBean: SessionBean,
    parser: CypherRewritingParser,
    detector: PermissionDetector,
    enforcer: CypherEnforcer,
    unparser: CypherRewritingUnparser
) : FuzzBaseRunner(sessionBean, parser, detector, enforcer, unparser), ApplicationRunner {

    private val userIdForReviewCache = ConcurrentHashMap<String, String>()

    override val reportDirSuffix: String? get() = "review-ownership"

    override val statsFlushInterval: Int
        get() = super.statsFlushInterval

    override fun run(args: ApplicationArguments) {
        Runtime.getRuntime().addShutdownHook(Thread { flushReport(debugCounters.total.get(), final = true) })
        runCoroutineFuzzer()
        flushReport(debugCounters.total.get(), final = true)
    }

    override fun constructFuzzingSettings(): FuzzSettings = fuzzSettings {
        pattern {
            length = 1..3
        }
        node {
            defectLabelProbability = 0.0
            defectPropertyProbability = 0.0
            defectPropertyTypeProbability = 0.0
            propertiesPerNode = 0..1
            labelsPerNode = 0..1
        }
        relationship {
            defectLabelProbability = 0.0
            defectTypeProbability = 0.0
            defectDirectionProbability = 0.0
            defectConnectionProbability = 0.0
        }
        where {
            probability = 0.1
            length = 1..3
        }
        returnSettings {
            propertyAccessProbability = 0.0
            aggregationProbability = 0.5
            aggregationFunctions = listOf("count")
            limitProbability = 0.0
            asteriskProbability = 0.0
            distinctProbability = 0.0
        }
    }

    override fun preCacheData(session: Session) {
        println("Preloading caches")

        val userIdForReview = mutableMapOf<String, String>()
        session.run(BULK_QUERY_USER_ID_FOR_REVIEW_ID).list { record ->
            val userId = record["userId"].toString()
            val reviewId = record["reviewId"].toString()
            if (reviewId in userIdForReview) {
                error("Review $reviewId already cached.")
            }
            userIdForReview.put(reviewId, userId)
        }
        userIdForReviewCache.putAll(userIdForReview)

        println("Pre-cached userIdForReview: ${userIdForReviewCache.size} entries")
    }

    // ========================================================================
    // Main Verification Flow
    // ========================================================================

    override fun doExecuteFuzzRun(
        fuzzItem: FuzzItem,
        iteration: Int,
        relevantCount: AtomicInteger
    ): FuzzRunContext? {
        val ctx = prepareQueries(fuzzItem, RELEVANT_LABELS_REVIEW, NON_EXISTENT_USER)

        updateDebugCounters(ctx, relevantCount)

        // Check 1: Rewritten result is a subset of the original (non-aggregated columns)
        checkRewrittenResultIsSubsetOfOriginal(ctx)

        // Check 2: No unauthorized nodes for non-existent user (non-aggregated columns)
        checkNoResultsForNonExistentUsers(ctx)

        // Check 3: Per-user correctness for non-aggregated Review nodes
        checkPerUserCorrectness(ctx, fuzzItem)

        // Check 4: Aggregation counts must be 0 for non-existent user
        checkAggregationForNonExistentUser(ctx)

        // Check 5: Per-user aggregation correctness via deaggregated helper query
        checkAggregationPerUserCorrectness(ctx, fuzzItem)

        // Check 6: Mutated query must not leak nodes (non-aggregated)
        checkMutatedQueryLeaks(ctx, fuzzItem)

        // Check 7: Mutated query must not leak via aggregation counts
        checkAggregationMutatedQueryLeaks(ctx, fuzzItem)

        if (ctx.errors.isNotEmpty()) {
            reportError(iteration, ctx)
        }

        flushReport(debugCounters.total.get())

        return ctx
    }

    // ========================================================================
    // Aggregation Utilities
    // ========================================================================

    /**
     * Extracts count variables from result keys.
     * E.g., key "count(n)" maps to variable name "n".
     */
    private fun extractCountVariables(keys: List<String>): Map<String, String> {
        return keys.mapNotNull { key ->
            COUNT_PATTERN.matchEntire(key)?.let { key to it.groupValues[1] }
        }.toMap()
    }

    /**
     * Replaces count(variable) with the raw variable in the query string.
     * E.g., "RETURN count(n), m" becomes "RETURN n, m".
     * This produces a query whose results can be filtered manually
     * and then aggregated for comparison.
     */
    private fun buildDeaggregatedQuery(query: String): String {
        return query.replace(COUNT_PATTERN, "$1")
    }

    /**
     * Returns the count keys that reference Review-labeled variables.
     * E.g., for keys ["count(n)", "m"] where n:Review, returns {"count(n)" to "n"}.
     */
    private fun reviewAggregationColumnNames(ctx: FuzzRunContext): Map<String, String> {
        val keys = ctx.originalTuples.firstOrNull()?.keys()?.toList() ?: return emptyMap()
        val countVars = extractCountVariables(keys)
        val reviewVars = ctx.metrics.variablesWithLabel("Review")
        return countVars.filter { it.value in reviewVars }
    }

    // ========================================================================
    // Check 2: No results for non-existent user (non-aggregated)
    // ========================================================================

    private fun checkNoResultsForNonExistentUsers(ctx: FuzzRunContext) {
        if (ctx.detections.isEmpty()) return

        if (ctx.rewrittenNodes.isNotEmpty()) {
            ctx.registerError(
                "### ERROR: Rewritten query for non-existent user contains ${ctx.rewrittenNodes.size} unauthorized reviews"
            )
        }
    }

    // ========================================================================
    // Check 3: Per-user correctness (non-aggregated)
    // ========================================================================

    /**
     * For each original Review node (from non-aggregated return columns), rewrites
     * the query for the Review's author and verifies soundness and completeness.
     *
     * Soundness: no reviews appear that aren't in the original results.
     * Completeness (single detection only): all authorized reviews are present.
     */
    private fun checkPerUserCorrectness(ctx: FuzzRunContext, fuzzItem: FuzzItem) {
        if (ctx.detections.isEmpty()) return
        val originalReviewIds = ctx.originalNodes.map { it["id"].toString() }.toSet()
        if (originalReviewIds.isEmpty()) return
        val hasMultipleDetections = ctx.detections.size > 1

        originalReviewIds.forEach { reviewId ->
            val authorizedUserId = userIdForReviewCache[reviewId]
                ?: error("Review $reviewId does not exist in the cache, so no userId could be found.")

            val rewrittenForUser = rewrite(fuzzItem.query, authorizedUserId)
            val rewrittenForUserReviewIds = getRelevantNodes(
                ctx.session.run(rewrittenForUser.rewrittenQuery, transactionConfig).list(),
                RELEVANT_LABELS_REVIEW
            ).map { it["id"].toString() }.toSet()

            // Soundness: no reviews should appear that aren't in the original results
            val additionalReviews = rewrittenForUserReviewIds - originalReviewIds
            if (additionalReviews.isNotEmpty()) {
                ctx.registerError(
                    "### ERROR: Rewritten query for user $authorizedUserId contains additional reviews: $additionalReviews\n" +
                            "    ${rewrittenForUser.rewrittenQuery}"
                )
            }

            // Completeness: all authorized reviews must be present
            // Skip when multiple detections exist — over-filtering may cause missing results
            if (!hasMultipleDetections) {
                val authorizedOriginalReviewIds = originalReviewIds.filter { userIdForReviewCache[it] == authorizedUserId }.toSet()
                val missingAuthorized = authorizedOriginalReviewIds - rewrittenForUserReviewIds
                if (missingAuthorized.isNotEmpty()) {
                    ctx.registerError(
                        "### ERROR: Rewritten query for user $authorizedUserId is missing authorized reviews: $missingAuthorized\n" +
                                "    ${rewrittenForUser.rewrittenQuery}"
                    )
                }
            }
        }
    }

    // ========================================================================
    // Check 4: Aggregation counts must be 0 for non-existent user
    // ========================================================================

    /**
     * When the rewriting system filters for a non-existent user, any count()
     * over a Review variable must produce 0. This verifies the authorization
     * filter is applied even when the result is aggregated — the rewriting
     * system must not be confused by the aggregation function.
     */
    private fun checkAggregationForNonExistentUser(ctx: FuzzRunContext) {
        if (ctx.detections.isEmpty()) return
        val reviewAggregations = reviewAggregationColumnNames(ctx)
        if (reviewAggregations.isEmpty()) return

        ctx.rewrittenTuples.forEach { record ->
            reviewAggregations.forEach { (key, variable) ->
                val count = record[key].asLong()
                if (count != 0L) {
                    ctx.registerError(
                        "### ERROR: Aggregation count for non-existent user is $count (expected 0) " +
                                "for $key (variable $variable)"
                    )
                }
            }
        }
    }

    // ========================================================================
    // Check 5: Per-user aggregation correctness
    // ========================================================================

    /**
     * Verifies that count(reviewVar) in the rewritten query for each user
     * matches the expected count. The expected count is computed by:
     * 1. Running a deaggregated query (count(n) replaced with n) without rewriting
     * 2. Filtering the raw results for reviews owned by the authorized user
     * 3. Counting authorized occurrences per group (grouped by non-aggregated columns)
     *
     * With multiple detections, only soundness is checked (actual <= expected)
     * because cross-variable filters may reduce results below the expected count.
     */
    private fun checkAggregationPerUserCorrectness(ctx: FuzzRunContext, fuzzItem: FuzzItem) {
        if (ctx.detections.isEmpty()) return
        val keys = ctx.originalTuples.firstOrNull()?.keys()?.toList() ?: return
        val reviewAggregationColumnNames = reviewAggregationColumnNames(ctx)
        if (reviewAggregationColumnNames.isEmpty()) return

        // Non-aggregated columns are the grouping columns (e.g., "m" in "RETURN count(n), m")
        val allAggregatedColumns = extractCountVariables(keys)
        val groupByColumns = keys.filter { it !in allAggregatedColumns }

        // Run deaggregated query (count(n) → n) without rewriting to get raw nodes
        val deaggregatedQuery = buildDeaggregatedQuery(fuzzItem.query)
        val deaggregatedResults = ctx.session.run(deaggregatedQuery, transactionConfig).list()

        // Each deaggregated record contributes one occurrence per review count variable
        data class CountEntry(val userId: String, val groupByValues: List<String>, val aggregatedColumn: String)

        val expectedByUser = deaggregatedResults.flatMap { record ->
                val groupByValues = groupByColumns.map { record[it].toString() }
                reviewAggregationColumnNames.mapNotNull { (aggregatedColumn, variable) ->
                    val value = record[variable]
                    if (value.type() == InternalTypeSystem.TYPE_SYSTEM.NODE()) {
                        val reviewId = value.asNode()["id"].toString()
                        val userId = userIdForReviewCache[reviewId] ?: error("Review $reviewId not in cache")
                        CountEntry(userId, groupByValues, aggregatedColumn)
                    } else null
                }
            }
            .groupBy { it.userId }
            .mapValues { (_, entries) ->
                entries.groupBy { it.groupByValues }
                    .mapValues { (_, grouped) ->
                        grouped.groupingBy { it.aggregatedColumn }.eachCount().mapValues { it.value.toLong() }
                    }
            }

        // For each user, rewrite the original (aggregated) query and compare counts
        expectedByUser.forEach { (userId, expectedGroups) ->
            val rewrittenForUser = rewrite(fuzzItem.query, userId)
            val rewrittenResults = ctx.session.run(rewrittenForUser.rewrittenQuery, transactionConfig).list()

            val actualByGroup = rewrittenResults.associate { record ->
                val groupByValues = groupByColumns.map { col -> record[col].toString() }
                val counts = reviewAggregationColumnNames.keys.associateWith { col -> record[col].asLong() }
                groupByValues to counts
            }

            expectedGroups.forEach { (groupByValues, expectedCounts) ->
                expectedCounts.forEach { (aggregatedColumn, expected) ->
                    val actual = actualByGroup[groupByValues]?.get(aggregatedColumn) ?: 0L

                    // Soundness: rewriting must not produce more results than authorized
                    if (actual > expected) {
                        ctx.registerError(
                            "### ERROR: Aggregation soundness: user $userId, group $groupByValues, $aggregatedColumn: " +
                                    "actual $actual > expected $expected\n" +
                                    "    ${rewrittenForUser.rewrittenQuery}"
                        )
                    }

                    // Completeness: all authorized reviews must be counted (single detection only)
                    val hasMultipleDetections = ctx.detections.size > 1
                    if (!hasMultipleDetections && actual != expected) {
                        ctx.registerError(
                            "### ERROR: Aggregation completeness: user $userId, group $groupByValues, $aggregatedColumn: " +
                                    "expected $expected, got $actual\n" +
                                    "    ${rewrittenForUser.rewrittenQuery}"
                        )
                    }
                }
            }
        }
    }

    // ========================================================================
    // Check 6: Mutated query leak detection (non-aggregated)
    // ========================================================================

    private fun checkMutatedQueryLeaks(ctx: FuzzRunContext, fuzzItem: FuzzItem) {
        val mutatedQuery = fuzzItem.mutatedQuery ?: return
        if (ctx.detections.isEmpty()) return

        val rewritten = rewrite(mutatedQuery, NON_EXISTENT_USER)
        val nodes = getRelevantNodes(
            ctx.session.run(rewritten.rewrittenQuery, transactionConfig).list(),
            RELEVANT_LABELS_REVIEW
        )

        if (nodes.isNotEmpty()) {
            ctx.registerError(
                "### ERROR: Mutated query returns nodes for non-existent user.\n" +
                        "    Mutated rewritten: ${rewritten.rewrittenQuery}"
            )
        }
    }

    // ========================================================================
    // Check 7: Mutated aggregation query leak detection
    // ========================================================================

    /**
     * For mutated queries with aggregation, verifies that count(reviewVar)
     * is 0 for a non-existent user. A non-zero count would indicate that
     * the rewriting system failed to filter the mutated query's aggregation.
     */
    private fun checkAggregationMutatedQueryLeaks(ctx: FuzzRunContext, fuzzItem: FuzzItem) {
        val mutatedQuery = fuzzItem.mutatedQuery ?: return
        if (ctx.detections.isEmpty()) return
        val reviewAggregations = reviewAggregationColumnNames(ctx)
        if (reviewAggregations.isEmpty()) return

        val rewritten = rewrite(mutatedQuery, NON_EXISTENT_USER)
        val mutatedResults = ctx.session.run(rewritten.rewrittenQuery, transactionConfig).list()

        mutatedResults.forEach { record ->
            reviewAggregations.forEach { (key, variable) ->
                val count = record[key].asLong()
                if (count != 0L) {
                    ctx.registerError(
                        "### ERROR: Mutated aggregation count for non-existent user is $count " +
                                "(expected 0) for $key (variable $variable)\n" +
                                "    Mutated rewritten: ${rewritten.rewrittenQuery}"
                    )
                }
            }
        }
    }

    // ========================================================================
    // Debug Counters
    // ========================================================================

    private val debugCounters = BaseDebugCounters()

    private fun updateDebugCounters(ctx: FuzzRunContext, relevantCount: AtomicInteger) {
        debugCounters.update(ctx, relevantCount)
        printStatsToConsole(debugCounters.total.get(), 1000)
    }

    override fun buildStatsText(header: String): String = debugCounters.statsText(header)

    companion object {
        private val RELEVANT_LABELS_REVIEW = listOf("Review")
        private val COUNT_PATTERN = Regex("""count\((\w+)\)""")
    }
}
