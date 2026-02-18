package at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer

import at.daho.cypherrewriting.cypherverificatorairbnb.SessionBean
import at.daho.cypherrewriting.cypherverificatorairbnb.model.FuzzRunContext
import at.daho.cypherrewriting.verification.FuzzItem
import at.daho.cypherrewriting.verification.FuzzMetrics
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstInternalNode
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstLeafValue
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstNode
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstType
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.PermissionDetector
import at.jku.faw.symspace.cypherrewriter.core.cypher.enforcer.CypherEnforcer
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import at.daho.cypherrewriting.verification.fuzzSettings
import at.daho.cypherrewriting.verification.FuzzSettings
import org.neo4j.driver.Record
import org.neo4j.driver.Session
import org.neo4j.driver.types.Node
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

private const val NON_EXISTENT_HOST = "0"
private const val BULK_QUERY_HOST_ID_FOR_REVIEW =
    "MATCH (r:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(h:Host) RETURN r.id as reviewId, h.id as hostId"
private const val BULK_QUERY_HOST_IDS_FOR_USER =
    "MATCH (u:User)-[:WROTE]->(r:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(h:Host) RETURN u.id as userId, h.id as hostId"

@Component
@Profile("identify-review-author-fuzzer")
class IdentifyReviewAuthorFuzzer(
    sessionBean: SessionBean,
    parser: CypherRewritingParser,
    detector: PermissionDetector,
    enforcer: CypherEnforcer,
    unparser: CypherRewritingUnparser
) : FuzzBaseRunner(sessionBean, parser, detector, enforcer, unparser), ApplicationRunner {

    override val reportDirSuffix: String? get() = "identify-review-author"

    override fun run(args: ApplicationArguments) {
        Runtime.getRuntime().addShutdownHook(Thread { flushReport(debugCounters.total.get(), final = true) })
        runCoroutineFuzzer()
        flushReport(debugCounters.total.get(), final = true)
    }

    override val statusInterval: Int get() = 10

    override fun constructFuzzingSettings(): FuzzSettings = fuzzSettings {
        pattern {
            patternsPerQuery = 1..1
            length = 2..2
        }
        node {
            defectLabelProbability = 0.0
            defectPropertyProbability = 0.0
            defectPropertyTypeProbability = 0.0
            propertiesPerNode = 0..0
            labelsPerNode = 1..1
            labelProbability = 1.0
            variableProbability = 1.0
            allowedLabels = setOf(LABEL_USER, LABEL_REVIEW)
        }
        relationship {
            defectLabelProbability = 0.0
            defectTypeProbability = 0.0
            defectDirectionProbability = 0.0
            defectConnectionProbability = 0.0
            variableProbability = 0.0
        }
        where {
            probability = 0.8
            length = 1..1
        }
        returnSettings {
            propertyAccessProbability = 0.0
            aggregationProbability = 0.0
            generateLimit = false
            generateSkip = false
            asteriskProbability = 0.0
            length = 1..2 
        }
    }

    // ========================================================================
    // Access Pattern Classification
    // ========================================================================

    /**
     * Classifies how a generated query accesses User and Review nodes.
     * This determines which verification checks are applicable.
     */
    private enum class AccessPattern {
        /** Review/User is just a traversal hop in the MATCH pattern — no Review data leaks.
         *
         * One of:
         * - User is filtered AND returned, Review is neither filtered nor returned.
         * - Review is filtered AND returned, User is neither filtered nor returned.
         */
        TRAVERSAL,

        /** WHERE filters User, RETURN returns Review (not User).
         *  Indirect access: Review data could leak through the User filter. */
        INDIRECT_USER_FILTERED_REVIEW_RETURNED,

        /** WHERE filters Review, RETURN returns User (not Review).
         *  Indirect access: User data could leak through the Review filter. */
        INDIRECT_REVIEW_FILTERED_USER_RETURNED,

        /** Any other combination (e.g., same type filtered and returned, missing vars). */
        OTHER
    }

    private fun classifyAccessPattern(metrics: FuzzMetrics): AccessPattern {
        val userVars = metrics.variablesWithLabel(LABEL_USER)
        val reviewVars = metrics.variablesWithLabel(LABEL_REVIEW)

        val userFiltered = (userVars intersect metrics.filteredVariables).isNotEmpty()
        val userReturned = (userVars intersect metrics.returnedVariables).isNotEmpty()
        val reviewFiltered = (reviewVars intersect metrics.filteredVariables).isNotEmpty()
        val reviewReturned = (reviewVars intersect metrics.returnedVariables).isNotEmpty()

        return when {
            userFiltered && userReturned && !reviewFiltered && !reviewReturned -> AccessPattern.TRAVERSAL
            !userFiltered && !userReturned && reviewFiltered && reviewReturned -> AccessPattern.TRAVERSAL
            userFiltered && !userReturned && reviewReturned -> AccessPattern.INDIRECT_USER_FILTERED_REVIEW_RETURNED
            reviewFiltered && !reviewReturned && userReturned -> AccessPattern.INDIRECT_REVIEW_FILTERED_USER_RETURNED
            else -> AccessPattern.OTHER
        }
    }

    // ========================================================================
    // Main Verification Flow
    // ========================================================================

    override fun doExecuteFuzzRun(fuzzItem: FuzzItem, iteration: Int, relevantCount: AtomicInteger): FuzzRunContext {
        val ctx = prepareQueries(fuzzItem, RELEVANT_LABELS_USER, NON_EXISTENT_HOST)
        val pattern = classifyAccessPattern(fuzzItem.metrics)

        updateDebugCounters(pattern, fuzzItem.metrics, ctx, relevantCount)

        // Check 1: Rewriting must not alter result structure or introduce new nodes
        checkRewrittenResultIsSubsetOfOriginal(ctx)

        // Check 2: Rewriting for a non-existent host must yield empty results
        checkNoResultsForNonExistentHost(ctx, pattern)

        // Check 3: For each authorized host, rewritten results must match original
        checkPerHostCorrectness(ctx, fuzzItem)

        // Check 4: Mutated query (flipped WHERE operator) must not leak data
        checkMutatedQueryLeaks(ctx, fuzzItem, pattern)

        if (ctx.errors.isNotEmpty()) {
            reportError(iteration, ctx)
        }

        flushReport(debugCounters.total.get())

        return ctx
    }

    // ========================================================================
    // Check 2: No results for non-existent host
    // ========================================================================

    /**
     * A query rewritten for a non-existent host must produce no User or Review
     * results, since no data is authorized for a host that doesn't exist.
     *
     * Skipped for [AccessPattern.TRAVERSAL]: Review is just a hop in the MATCH
     * pattern and is not returned, so no Review data leaks and no authorization
     * is needed. The permission system won't inject a filter, so the rewritten
     * query equals the original and legitimately returns results.
     *
     * Skipped for [AccessPattern.OTHER] when the detector found no patterns to
     * rewrite: these are legitimately undetected (e.g., Review filtered + Review
     * returned with User not returned — no authorship leak). The rewritten query
     * equals the original and results are expected.
     *
     * For INDIRECT patterns, this check runs even with no detections — that would
     * indicate a detector bug (filter should have been injected but wasn't).
     */
    private fun checkNoResultsForNonExistentHost(ctx: FuzzRunContext, pattern: AccessPattern) {
        if (pattern == AccessPattern.TRAVERSAL) return
        if (pattern == AccessPattern.OTHER && ctx.detections.isEmpty()) return

        // User nodes from the main check
        if (ctx.rewrittenNodes.isNotEmpty()) {
            ctx.registerError(
                "### ERROR: Rewritten query for non-existent host contains ${ctx.rewrittenNodes.size} unauthorized users"
            )
        }

        // Also check the other way around
        val rewrittenReviews = getRelevantNodes(ctx.rewrittenTuples, RELEVANT_LABELS_REVIEW)
        if (rewrittenReviews.isNotEmpty()) {
            ctx.registerError(
                "### ERROR: Rewritten query for non-existent host contains ${rewrittenReviews.size} unauthorized reviews"
            )
        }
    }

    // ========================================================================
    // Check 3: Per-host correctness
    // ========================================================================

    /**
     * For each host referenced in the original results, rewrites the query for
     * that specific host and verifies:
     * - No authorized results are missing (completeness).
     * - No new results appear that weren't in the original (soundness).
     *
     * Only runs when the permission system actually detected patterns to rewrite.
     */
    private fun checkPerHostCorrectness(ctx: FuzzRunContext, fuzzItem: FuzzItem) {
        if (ctx.detections.isEmpty()) return

        checkPerHostCorrectnessForUsers(ctx, fuzzItem)
        checkPerHostCorrectnessForReviews(ctx, fuzzItem)
    }

    private fun checkPerHostCorrectnessForUsers(ctx: FuzzRunContext, fuzzItem: FuzzItem) {
        val originalUserIds = ctx.originalNodes.map { it["id"].toString() }.toSet()
        val originalReviews = getRelevantNodes(ctx.originalTuples, RELEVANT_LABELS_REVIEW)

        // Determine authorized user IDs per host and which hosts to check.
        // When reviews are in the results, correlate per row (review→host→users).
        // This gives exact authorized sets because we know which reviews (and thus
        // which host connections) actually matched the query's WHERE clause.
        //
        // When only users are returned, use the user→host cache to find hosts to
        // check, but only verify soundness (no unauthorized users added). We cannot
        // check completeness because the cache maps users to ALL hosts they've ever
        // reviewed for, ignoring the query's WHERE filter on reviews.
        val reviewsInResults = originalReviews.isNotEmpty()
        val authorizedUserIdsByHost: Map<String, Set<String>>
        val hostIds: Set<String>

        if (reviewsInResults) {
            authorizedUserIdsByHost = buildAuthorizedUserIdsByHost(ctx.originalTuples)
            hostIds = originalReviews
                .mapNotNull { getHostIdForReview(it["id"].toString()) }
                .toSet()
        } else {
            val result = mutableMapOf<String, MutableSet<String>>()
            for (userId in originalUserIds) {
                for (hostId in getHostIdsForUser(userId)) {
                    result.getOrPut(hostId) { mutableSetOf() }.add(userId)
                }
            }
            authorizedUserIdsByHost = result
            hostIds = result.keys
        }

        for (hostId in hostIds) {
            val authorizedOriginalUserIds = authorizedUserIdsByHost[hostId] ?: emptySet()
            val rewrittenForHost = rewrite(fuzzItem.query, hostId)
            val rewrittenForHostUserIds = getRelevantNodes(
                ctx.session.run(rewrittenForHost.rewrittenQuery, transactionConfig).list(),
                RELEVANT_LABELS_USER
            ).map { it["id"].toString() }.toSet()

            // Completeness: only when reviews are in results (exact authorized set known)
            if (reviewsInResults) {
                val missingAuthorized = authorizedOriginalUserIds - rewrittenForHostUserIds
                if (missingAuthorized.isNotEmpty()) {
                    ctx.registerError(
                        "### ERROR: Rewritten query for host $hostId is missing authorized users: $missingAuthorized\n" +
                                "    ${rewrittenForHost.rewrittenQuery}"
                    )
                }
            }

            // Soundness: no users should appear that aren't in the original results
            val addedUsers = rewrittenForHostUserIds - originalUserIds
            if (addedUsers.isNotEmpty()) {
                ctx.registerError(
                    "### ERROR: Rewritten query for host $hostId contains users not in original: $addedUsers\n" +
                            "    ${rewrittenForHost.rewrittenQuery}"
                )
            }
        }
    }

    /**
     * Builds a mapping from hostId to the set of user IDs authorized for that host,
     * by correlating User and Review nodes within each result row.
     * A user is authorized for a host if they appear in the same result row as a review
     * belonging to that host's listing.
     */
    private fun buildAuthorizedUserIdsByHost(tuples: List<Record>): Map<String, Set<String>> {
        val result = mutableMapOf<String, MutableSet<String>>()
        for (record in tuples) {
            val userIds = record.keys()
                .filter { key -> isNodeWithLabel(key, record, LABEL_USER) }
                .map { key -> record[key].asNode()["id"].toString() }
            val reviewIds = record.keys()
                .filter { key -> isNodeWithLabel(key, record, LABEL_REVIEW) }
                .map { key -> record[key].asNode()["id"].toString() }
            for (reviewId in reviewIds) {
                val hostId = getHostIdForReview(reviewId) ?: continue
                val hostSet = result.getOrPut(hostId) { mutableSetOf() }
                hostSet.addAll(userIds)
            }
        }
        return result
    }

    private fun checkPerHostCorrectnessForReviews(ctx: FuzzRunContext, fuzzItem: FuzzItem) {
        val originalReviews = getRelevantNodes(ctx.originalTuples, RELEVANT_LABELS_REVIEW)

        forEachDistinctHost(originalReviews) { hostId ->
            val rewrittenForHost = rewrite(fuzzItem.query, hostId)
            val rewrittenForHostReviewIds = getRelevantNodes(
                ctx.session.run(rewrittenForHost.rewrittenQuery, transactionConfig).list(),
                RELEVANT_LABELS_REVIEW
            ).map { it["id"].toString() }.toSet()

            val authorizedOriginalReviews = originalReviews
                .map { it["id"].toString() }
                .filter { getHostIdForReview(it) == hostId }
                .toSet()
            val missingAuthorized = authorizedOriginalReviews - rewrittenForHostReviewIds
            if (missingAuthorized.isNotEmpty()) {
                ctx.registerError(
                    "### ERROR: Rewritten query for host $hostId is missing authorized reviews: $missingAuthorized\n" +
                            "    ${rewrittenForHost.rewrittenQuery}"
                )
            }

            val addedReviews = rewrittenForHostReviewIds - authorizedOriginalReviews
            if (addedReviews.isNotEmpty()) {
                ctx.registerError(
                    "### ERROR: Rewritten query for host $hostId contains reviews not in original: $addedReviews\n" +
                            "    ${rewrittenForHost.rewrittenQuery}"
                )
            }
        }
    }

    /**
     * Iterates over each distinct host referenced by the given review nodes.
     * Uses [getHostIdForReview] to look up the host, deduplicates by host ID.
     */
    private inline fun forEachDistinctHost(
        reviews: List<Node>,
        action: (hostId: String) -> Unit
    ) {
        val checkedHostIds = mutableSetOf<String>()
        for (review in reviews) {
            val hostId = getHostIdForReview(review["id"].toString()) ?: continue
            if (checkedHostIds.add(hostId)) {
                action(hostId)
            }
        }
    }

    // ========================================================================
    // Check 4: Mutated query leak detection
    // ========================================================================

    /**
     * Verifies that the mutated query (flipped WHERE operator), when rewritten
     * for a non-existent host, also produces no results. Then, for each valid
     * host where the filtered (non-returned) variable contains unauthorized
     * nodes, verifies that the mutation does not change the returned results.
     * A difference indicates an indirect access violation: the non-returned
     * variable's filter leaks information into the returned results.
     *
     * Only applicable for indirect access patterns where the filtered and
     * returned node types differ.
     */
    private fun checkMutatedQueryLeaks(ctx: FuzzRunContext, fuzzItem: FuzzItem, pattern: AccessPattern) {
        val mutatedQuery = fuzzItem.mutatedQuery ?: return
        if (ctx.detections.isEmpty()) return

        val relevantLabels: List<String>
        val filteredLabels: List<String>
        val filteredVarNames: Set<String>

        when (pattern) {
            AccessPattern.INDIRECT_USER_FILTERED_REVIEW_RETURNED -> {
                relevantLabels = RELEVANT_LABELS_REVIEW
                filteredLabels = RELEVANT_LABELS_USER
                filteredVarNames = fuzzItem.metrics.variablesWithLabel(LABEL_USER) intersect fuzzItem.metrics.filteredVariables
            }
            AccessPattern.INDIRECT_REVIEW_FILTERED_USER_RETURNED -> {
                relevantLabels = RELEVANT_LABELS_USER
                filteredLabels = RELEVANT_LABELS_REVIEW
                filteredVarNames = fuzzItem.metrics.variablesWithLabel(LABEL_REVIEW) intersect fuzzItem.metrics.filteredVariables
            }
            else -> return
        }

        debugCounters.indirectAccessChecked.incrementAndGet()

        // Sanity check: mutated query for non-existent host must return nothing
        val rewrittenNonExistent = rewrite(mutatedQuery, NON_EXISTENT_HOST)
        val nodesNonExistent = getRelevantNodes(
            ctx.session.run(rewrittenNonExistent.rewrittenQuery, transactionConfig).list(),
            relevantLabels
        )
        if (nodesNonExistent.isNotEmpty()) {
            ctx.registerError(
                "### ERROR: Mutated query returns nodes for non-existent host.\n" +
                        "    Mutated rewritten: ${rewrittenNonExistent.rewrittenQuery}"
            )
        }

        // Get filtered (non-returned) nodes by adding them to RETURN and executing
        val modifiedQuery = addVariablesToReturn(fuzzItem.query, filteredVarNames)
        val modifiedResults = ctx.session.run(modifiedQuery, transactionConfig).list()
        val filteredNodes = getRelevantNodes(modifiedResults, filteredLabels)
        if (filteredNodes.isEmpty()) return

        // Get distinct hosts from the returned nodes in the original results
        val hostIds = getHostIdsForPattern(ctx, pattern)

        for (hostId in hostIds) {
            // Only check hosts where the filtered variable contains unauthorized nodes
            val hasUnauthorizedNodes = when (pattern) {
                AccessPattern.INDIRECT_USER_FILTERED_REVIEW_RETURNED ->
                    filteredNodes.any { user -> hostId !in getHostIdsForUser(user["id"].toString()) }
                AccessPattern.INDIRECT_REVIEW_FILTERED_USER_RETURNED ->
                    filteredNodes.any { review -> getHostIdForReview(review["id"].toString()) != hostId }
                else -> false
            }
            if (!hasUnauthorizedNodes) continue

            // Rewrite both queries for this host
            val rewrittenOriginal = rewrite(fuzzItem.query, hostId)
            val rewrittenMutated = rewrite(mutatedQuery, hostId)

            // Check whether filtered nodes after rewriting contain unauthorized data
            val rewrittenOriginalFiltered = getFilteredNodesFromRewritten(
                ctx.session, rewrittenOriginal.rewrittenQuery, filteredVarNames, filteredLabels
            )
            val rewrittenMutatedFiltered = getFilteredNodesFromRewritten(
                ctx.session, rewrittenMutated.rewrittenQuery, filteredVarNames, filteredLabels
            )

            val originalFilteredHasUnauthorized = hasUnauthorizedFilteredNodes(rewrittenOriginalFiltered, pattern, hostId)
            val mutatedFilteredHasUnauthorized = hasUnauthorizedFilteredNodes(rewrittenMutatedFiltered, pattern, hostId)

            if (!originalFilteredHasUnauthorized && !mutatedFilteredHasUnauthorized) continue

            debugCounters.unauthorizedFilteredAfterRewrite.incrementAndGet()

            // If either rewritten query still has unauthorized filtered nodes,
            // the returned results must be identical
            val originalNodeIds = getRelevantNodes(
                ctx.session.run(rewrittenOriginal.rewrittenQuery, transactionConfig).list(),
                relevantLabels
            ).map { it["id"].toString() }.toSet()

            val mutatedNodeIds = getRelevantNodes(
                ctx.session.run(rewrittenMutated.rewrittenQuery, transactionConfig).list(),
                relevantLabels
            ).map { it["id"].toString() }.toSet()

            if (originalNodeIds != mutatedNodeIds) {
                debugCounters.unauthorizedFilteredWithDifferentResults.incrementAndGet()
                ctx.registerError(
                    "### ERROR: Indirect access violation for host $hostId — " +
                            "mutated query produces different results.\n" +
                            "    Only in original: ${originalNodeIds - mutatedNodeIds}\n" +
                            "    Only in mutated:  ${mutatedNodeIds - originalNodeIds}\n" +
                            "    Original rewritten: ${rewrittenOriginal.rewrittenQuery}\n" +
                            "    Mutated rewritten:  ${rewrittenMutated.rewrittenQuery}"
                )
            }
        }
    }

    /**
     * Returns the set of host IDs referenced by the returned nodes in the
     * original results, based on the access pattern.
     */
    private fun getHostIdsForPattern(ctx: FuzzRunContext, pattern: AccessPattern): Set<String> {
        return when (pattern) {
            AccessPattern.INDIRECT_USER_FILTERED_REVIEW_RETURNED -> {
                val reviews = getRelevantNodes(ctx.originalTuples, RELEVANT_LABELS_REVIEW)
                reviews.mapNotNull { getHostIdForReview(it["id"].toString()) }.toSet()
            }
            AccessPattern.INDIRECT_REVIEW_FILTERED_USER_RETURNED -> {
                val users = getRelevantNodes(ctx.originalTuples, RELEVANT_LABELS_USER)
                users.flatMap { getHostIdsForUser(it["id"].toString()) }.toSet()
            }
            else -> emptySet()
        }
    }

    /**
     * Creates a modified version of the query that also returns the given
     * variables. Parses the query to AST, adds the variables to the RETURN
     * clause, and unparses back to a query string.
     */
    private fun addVariablesToReturn(query: String, varNames: Set<String>): String {
        val ast = parser.parse(query) as AstInternalNode
        val returnNode = findReturnNode(ast) ?: return query

        for (varName in varNames) {
            val alreadyReturned = returnNode.elements.any {
                it is AstLeafValue && it.type == AstType.VARIABLE && it.value == varName
            }
            if (alreadyReturned) continue

            val newVar = AstLeafValue(AstType.VARIABLE, varName)
            val insertIndex = returnNode.elements.indexOfFirst {
                it.type in setOf(AstType.ORDER_BY, AstType.SKIP, AstType.LIMIT)
            }
            if (insertIndex >= 0) {
                returnNode.elements.add(insertIndex, newVar)
            } else {
                returnNode.elements.add(newVar)
            }
        }

        return unparser.render(ast)
    }

    private fun getFilteredNodesFromRewritten(
        session: Session, rewrittenQuery: String, filteredVarNames: Set<String>, filteredLabels: List<String>
    ): List<Node> {
        val modifiedRewritten = addVariablesToReturn(rewrittenQuery, filteredVarNames)
        val results = session.run(modifiedRewritten, transactionConfig).list()
        return getRelevantNodes(results, filteredLabels)
    }

    private fun hasUnauthorizedFilteredNodes(
        filteredNodes: List<Node>, pattern: AccessPattern, hostId: String
    ): Boolean {
        return when (pattern) {
            AccessPattern.INDIRECT_USER_FILTERED_REVIEW_RETURNED ->
                filteredNodes.any { user -> hostId !in getHostIdsForUser(user["id"].toString()) }
            AccessPattern.INDIRECT_REVIEW_FILTERED_USER_RETURNED ->
                filteredNodes.any { review -> getHostIdForReview(review["id"].toString()) != hostId }
            else -> false
        }
    }

    private fun findReturnNode(node: AstNode): AstInternalNode? {
        if (node is AstInternalNode) {
            if (node.type == AstType.RETURN) return node
            for (child in node.elements) {
                findReturnNode(child)?.let { return it }
            }
        }
        return null
    }

    // ========================================================================
    // Cache
    // ========================================================================

    private val hostIdForReviewCache = ConcurrentHashMap<String, String>()
    private val hostIdsForUserCache = ConcurrentHashMap<String, Set<String>>()

    override fun preCacheData(session: Session) {
        println("Preloading caches")

        session.run(BULK_QUERY_HOST_ID_FOR_REVIEW).list().forEach { record ->
            val reviewId = record["reviewId"].toString()
            val hostId = record["hostId"].toString()
            hostIdForReviewCache[reviewId] = hostId
        }
        println("Pre-cached hostIdForReview: ${hostIdForReviewCache.size} entries")

        val hostIdsForUser = mutableMapOf<String, MutableSet<String>>()
        session.run(BULK_QUERY_HOST_IDS_FOR_USER).list().forEach { record ->
            val userId = record["userId"].toString()
            val hostId = record["hostId"].toString()
            hostIdsForUser.getOrPut(userId) { mutableSetOf() }.add(hostId)
        }
        hostIdsForUserCache.putAll(hostIdsForUser)
        println("Pre-cached hostIdsForUser: ${hostIdsForUserCache.size} entries")
    }

    private fun getHostIdForReview(reviewId: String): String? {
        return hostIdForReviewCache[reviewId]
    }

    private fun getHostIdsForUser(userId: String): Set<String> {
        return hostIdsForUserCache[userId] ?: emptySet()
    }

    // ========================================================================
    // Debug Counters
    // ========================================================================

    private val debugCounters = object {
        val total = AtomicInteger(0)
        val sameLabels = AtomicInteger(0)
        val noUserVar = AtomicInteger(0)
        val noReviewVar = AtomicInteger(0)
        val whereNotUserOrReview = AtomicInteger(0)
        val returnNotUserOrReview = AtomicInteger(0)
        val whereAndReturnSameType = AtomicInteger(0)
        val noIndirectPattern = AtomicInteger(0)
        val emptyResult = AtomicInteger(0)
        val relevant = AtomicInteger(0)
        val indirectAccessChecked = AtomicInteger(0)
        val unauthorizedFilteredAfterRewrite = AtomicInteger(0)
        val unauthorizedFilteredWithDifferentResults = AtomicInteger(0)
    }

    private fun updateDebugCounters(
        pattern: AccessPattern,
        metrics: FuzzMetrics,
        ctx: FuzzRunContext,
        relevantCount: AtomicInteger
    ) {
        val userVars = metrics.variablesWithLabel(LABEL_USER)
        val reviewVars = metrics.variablesWithLabel(LABEL_REVIEW)

        debugCounters.total.incrementAndGet()
        if (userVars.isEmpty()) debugCounters.noUserVar.incrementAndGet()
        if (reviewVars.isEmpty()) debugCounters.noReviewVar.incrementAndGet()
        if (userVars.isNotEmpty() && reviewVars.isNotEmpty() && userVars == reviewVars) {
            debugCounters.sameLabels.incrementAndGet()
        }
        if ((userVars intersect metrics.filteredVariables).isEmpty()
            && (reviewVars intersect metrics.filteredVariables).isEmpty()
        ) {
            debugCounters.whereNotUserOrReview.incrementAndGet()
        }
        if ((userVars intersect metrics.returnedVariables).isEmpty()
            && (reviewVars intersect metrics.returnedVariables).isEmpty()
        ) {
            debugCounters.returnNotUserOrReview.incrementAndGet()
        }

        val filteredIsUser = (userVars intersect metrics.filteredVariables).isNotEmpty()
        val filteredIsReview = (reviewVars intersect metrics.filteredVariables).isNotEmpty()
        val returnedIsUser = (userVars intersect metrics.returnedVariables).isNotEmpty()
        val returnedIsReview = (reviewVars intersect metrics.returnedVariables).isNotEmpty()
        if ((filteredIsUser && returnedIsUser) || (filteredIsReview && returnedIsReview)) {
            debugCounters.whereAndReturnSameType.incrementAndGet()
        }

        val isIndirect = pattern == AccessPattern.INDIRECT_USER_FILTERED_REVIEW_RETURNED
                || pattern == AccessPattern.INDIRECT_REVIEW_FILTERED_USER_RETURNED

        if (!isIndirect) {
            debugCounters.noIndirectPattern.incrementAndGet()
        } else if (ctx.originalTuples.isEmpty()) {
            debugCounters.emptyResult.incrementAndGet()
        } else {
            debugCounters.relevant.incrementAndGet()
            relevantCount.incrementAndGet()
        }

        printDebugStats()
    }

    override fun buildStatsText(header: String): String = buildString {
        appendLine(header)
        appendLine("  Same labels (User-User/Review-Review): ${debugCounters.sameLabels.get()}")
        appendLine("  No User var:    ${debugCounters.noUserVar.get()}")
        appendLine("  No Review var:  ${debugCounters.noReviewVar.get()}")
        appendLine("  WHERE not User/Review: ${debugCounters.whereNotUserOrReview.get()}")
        appendLine("  RETURN not User/Review: ${debugCounters.returnNotUserOrReview.get()}")
        appendLine("  WHERE+RETURN same type: ${debugCounters.whereAndReturnSameType.get()}")
        appendLine("  No indirect pattern: ${debugCounters.noIndirectPattern.get()}")
        appendLine("  Empty result:   ${debugCounters.emptyResult.get()}")
        appendLine("  Relevant:       ${debugCounters.relevant.get()}")
        appendLine("  Indirect access checked: ${debugCounters.indirectAccessChecked.get()}")
        appendLine("  Unauthorized filtered after rewrite: ${debugCounters.unauthorizedFilteredAfterRewrite.get()}")
        appendLine("  ... with different results: ${debugCounters.unauthorizedFilteredWithDifferentResults.get()}")
    }

    private fun printDebugStats() {
        printStatsToConsole(debugCounters.total.get())
    }

    companion object {
        private const val LABEL_USER = "User"
        private const val LABEL_REVIEW = "Review"
        private val RELEVANT_LABELS_USER = listOf(LABEL_USER)
        private val RELEVANT_LABELS_REVIEW = listOf(LABEL_REVIEW)
    }
}
