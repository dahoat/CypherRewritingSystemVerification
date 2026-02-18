package at.daho.cypherrewriting.cypherverificatorairbnb

import at.daho.cypherrewriting.verification.FuzzItem
import at.daho.cypherrewriting.verification.FuzzMetrics
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import org.neo4j.driver.TransactionConfig
import java.util.concurrent.atomic.AtomicInteger

/*
 * Tests for IdentifyReviewAuthorFuzzer.checkMutatedQueryLeaks:
 * verifies that flipping WHERE operators in indirect access queries
 * correctly detects (or does not detect) indirect access violations.
 *
 * This test class was generated using AI tools (Claude Code).
 */
class CheckMutatedQueryLeaksTest {

    // =========================================================================
    // Guard clause tests (early returns before per-host comparison)
    // =========================================================================

    /**
     * When detector finds no patterns, checkMutatedQueryLeaks returns early
     * (no rewriting possible means no leak to detect).
     */
    @Test
    fun mutatedQuerySkipsWhenNoDetections() {
        val fixture = createFuzzerTestFixture(withDetections = false)

        val metrics = FuzzMetrics(
            labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
            filteredVariables = setOf("u"),
            returnedVariables = setOf("r")
        )
        val fuzzItem = FuzzItem(
            "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r",
            "MATCH (r:Review)--(u:User) WHERE u.id <> 1 RETURN r",
            metrics
        )

        val ctx = fixture.fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

        assertTrue(ctx.errors.isEmpty(),
            "No detections means no mutation check. Errors: ${ctx.errors}")
        // The mutated query should never be parsed since we return early
        verify(fixture.parser, never()).parse(eq("MATCH (r:Review)--(u:User) WHERE u.id <> 1 RETURN r"))
    }

    /**
     * TRAVERSAL pattern (User filtered+returned, Review neither) is not an indirect
     * access pattern, so checkMutatedQueryLeaks returns at the `else -> return` branch.
     */
    @Test
    fun mutatedQuerySkipsForTraversalPattern() {
        val fixture = createFuzzerTestFixture()

        val metrics = FuzzMetrics(
            labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
            filteredVariables = setOf("u"),
            returnedVariables = setOf("u")  // User filtered+returned = TRAVERSAL
        )
        val fuzzItem = FuzzItem(
            "MATCH (u:User)--(r:Review) WHERE u.id = 1 RETURN u",
            "MATCH (u:User)--(r:Review) WHERE u.id <> 1 RETURN u",
            metrics
        )

        val ctx = fixture.fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

        assertTrue(ctx.errors.isEmpty(),
            "Traversal pattern should not trigger mutation check. Errors: ${ctx.errors}")
    }

    /**
     * Indirect pattern with detections but addVariablesToReturn returns no filtered
     * nodes (the WHERE-filtered variable doesn't match any rows when added to RETURN).
     * checkMutatedQueryLeaks returns early at the filteredNodes.isEmpty() guard.
     */
    @Test
    fun mutatedQuerySkipsWhenFilteredNodesEmpty() {
        // Use real AST with RETURN node so addVariablesToReturn calls render
        val fixture = createFuzzerTestFixture(withAstReturnNode = true)

        val metrics = FuzzMetrics(
            labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
            filteredVariables = setOf("u"),
            returnedVariables = setOf("r")
        )
        val fuzzItem = FuzzItem(
            "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r",
            "MATCH (r:Review)--(u:User) WHERE u.id <> 1 RETURN r",
            metrics
        )

        // All session.run calls return empty by default, so:
        // - original result: empty → no reviews → checkPerHostCorrectness skips
        // - mutated rewrite for non-existent host: empty → sanity check passes
        // - addVariablesToReturn query: empty → filteredNodes empty → return
        val ctx = fixture.fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

        assertTrue(ctx.errors.isEmpty(),
            "Empty filtered nodes should produce no mutation check errors. Errors: ${ctx.errors}")
    }

    // =========================================================================
    // Per-host comparison tests (full checkMutatedQueryLeaks flow)
    // =========================================================================

    /**
     * INDIRECT_USER_FILTERED_REVIEW_RETURNED: original and mutated rewritten queries
     * return the same Review node IDs for a host → no error.
     *
     * Setup: User filtered, Review returned. Review 42 belongs to host H1.
     * User 100 (the filtered node) belongs to host H2 (unauthorized for H1).
     * Both original and mutated rewrites for H1 return Review 42 → match → no error.
     */
    @Test
    fun mutatedQueryNoErrorWhenResultsMatchForUserFilteredReviewReturned() {
        val fixture = createFuzzerTestFixture(withAstReturnNode = true)

        val originalQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r"
        val mutatedQuery = "MATCH (r:Review)--(u:User) WHERE u.id <> 1 RETURN r"
        val reviewNode42 = mockNode("Review", "42")
        val userNode100 = mockNode("User", "100")

        // Original query returns Review 42
        val originalResult = mockResult(listOf(mockRecord("r" to reviewNode42)))
        whenever(fixture.session.run(eq(originalQuery), any<TransactionConfig>()))
            .thenReturn(originalResult)

        populateCache(fixture,
            reviewToHost = mapOf("42" to "H1"),
            userToHosts = mapOf("100" to setOf("H2"))
        )

        // Render calls in order:
        // 1: prepareQueries rewrite → "PREP_REWRITTEN"
        // 2: checkPerHostCorrectnessForUsers rewrite(query,H1) → "HOST_USER_CHECK"
        // 3: checkPerHostCorrectnessForReviews rewrite(query,H1) → "HOST_REVIEW_CHECK"
        // 4: checkMutatedQueryLeaks rewrite(mutated,"0") → "MUT_NONEXIST"
        // 5: addVariablesToReturn render → "MODIFIED_QUERY"
        // 6: rewrite(original,H1) → "ORIG_HOST"
        // 7: rewrite(mutated,H1) → "MUT_HOST"
        // 8: getFilteredNodesFromRewritten addVariablesToReturn(ORIG_HOST) → "ORIG_HOST_FILTERED"
        // 9: getFilteredNodesFromRewritten addVariablesToReturn(MUT_HOST) → "MUT_HOST_FILTERED"
        whenever(fixture.unparser.render(any())).thenReturn(
            "PREP_REWRITTEN",
            "HOST_USER_CHECK",
            "HOST_REVIEW_CHECK",
            "MUT_NONEXIST",
            "MODIFIED_QUERY",
            "ORIG_HOST",
            "MUT_HOST",
            "ORIG_HOST_FILTERED",
            "MUT_HOST_FILTERED"
        )

        // Pre-create all mock results to avoid UnfinishedStubbingException
        val emptyResult = mockResult()
        val review42Result = mockResult(listOf(mockRecord("r" to reviewNode42)))
        val user100Result = mockResult(listOf(mockRecord("u" to userNode100)))

        // Session.run for each distinct rewritten query:
        whenever(fixture.session.run(eq("PREP_REWRITTEN"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("HOST_USER_CHECK"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("HOST_REVIEW_CHECK"), any<TransactionConfig>()))
            .thenReturn(review42Result)
        whenever(fixture.session.run(eq("MUT_NONEXIST"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("MODIFIED_QUERY"), any<TransactionConfig>()))
            .thenReturn(user100Result)
        whenever(fixture.session.run(eq("ORIG_HOST"), any<TransactionConfig>()))
            .thenReturn(review42Result)
        // MUT_HOST: same Review 42 (no leak)
        whenever(fixture.session.run(eq("MUT_HOST"), any<TransactionConfig>()))
            .thenReturn(review42Result)
        // Rewritten filtered nodes: User 100 is unauthorized for H1 (belongs to H2)
        whenever(fixture.session.run(eq("ORIG_HOST_FILTERED"), any<TransactionConfig>()))
            .thenReturn(user100Result)
        whenever(fixture.session.run(eq("MUT_HOST_FILTERED"), any<TransactionConfig>()))
            .thenReturn(user100Result)

        val metrics = FuzzMetrics(
            labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
            filteredVariables = setOf("u"),
            returnedVariables = setOf("r")
        )
        val fuzzItem = FuzzItem(originalQuery, mutatedQuery, metrics)

        val ctx = fixture.fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

        assertTrue(ctx.errors.isEmpty(),
            "Matching results should produce no indirect access violation. Errors: ${ctx.errors}")
    }

    /**
     * INDIRECT_USER_FILTERED_REVIEW_RETURNED: mutated rewritten query returns different
     * Review node IDs than the original → "Indirect access violation" error.
     *
     * Setup: same as above but mutated rewrite for H1 returns {Review 42, Review 99}
     * while original rewrite returns {Review 42} → difference detected.
     */
    @Test
    fun mutatedQueryDetectsLeakForUserFilteredReviewReturned() {
        val fixture = createFuzzerTestFixture(withAstReturnNode = true)

        val originalQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r"
        val mutatedQuery = "MATCH (r:Review)--(u:User) WHERE u.id <> 1 RETURN r"
        val reviewNode42 = mockNode("Review", "42")
        val reviewNode99 = mockNode("Review", "99")
        val userNode100 = mockNode("User", "100")

        val originalResult = mockResult(listOf(mockRecord("r" to reviewNode42)))
        whenever(fixture.session.run(eq(originalQuery), any<TransactionConfig>()))
            .thenReturn(originalResult)

        populateCache(fixture,
            reviewToHost = mapOf("42" to "H1", "99" to "H1"),
            userToHosts = mapOf("100" to setOf("H2"))
        )

        whenever(fixture.unparser.render(any())).thenReturn(
            "PREP_REWRITTEN",
            "HOST_USER_CHECK",
            "HOST_REVIEW_CHECK",
            "MUT_NONEXIST",
            "MODIFIED_QUERY",
            "ORIG_HOST",
            "MUT_HOST",
            "ORIG_HOST_FILTERED",
            "MUT_HOST_FILTERED"
        )

        // Pre-create all mock results
        val emptyResult = mockResult()
        val review42Result = mockResult(listOf(mockRecord("r" to reviewNode42)))
        val user100Result = mockResult(listOf(mockRecord("u" to userNode100)))
        val review42And99Result = mockResult(listOf(
            mockRecord("r" to reviewNode42),
            mockRecord("r" to reviewNode99)
        ))

        whenever(fixture.session.run(eq("PREP_REWRITTEN"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("HOST_USER_CHECK"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("HOST_REVIEW_CHECK"), any<TransactionConfig>()))
            .thenReturn(review42Result)
        whenever(fixture.session.run(eq("MUT_NONEXIST"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("MODIFIED_QUERY"), any<TransactionConfig>()))
            .thenReturn(user100Result)
        whenever(fixture.session.run(eq("ORIG_HOST"), any<TransactionConfig>()))
            .thenReturn(review42Result)
        // MUT_HOST: {Review 42, Review 99} → different!
        whenever(fixture.session.run(eq("MUT_HOST"), any<TransactionConfig>()))
            .thenReturn(review42And99Result)
        // Rewritten filtered nodes: User 100 is unauthorized for H1 (belongs to H2)
        whenever(fixture.session.run(eq("ORIG_HOST_FILTERED"), any<TransactionConfig>()))
            .thenReturn(user100Result)
        whenever(fixture.session.run(eq("MUT_HOST_FILTERED"), any<TransactionConfig>()))
            .thenReturn(user100Result)

        val metrics = FuzzMetrics(
            labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
            filteredVariables = setOf("u"),
            returnedVariables = setOf("r")
        )
        val fuzzItem = FuzzItem(originalQuery, mutatedQuery, metrics)

        val ctx = fixture.fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

        assertTrue(ctx.errors.any { it.contains("Indirect access violation") },
            "Differing results must trigger indirect access violation. Errors: ${ctx.errors}")
    }

    /**
     * INDIRECT_REVIEW_FILTERED_USER_RETURNED: mutated rewritten query returns different
     * User node IDs than the original → "Indirect access violation" error.
     *
     * Setup: Review filtered, User returned. User 100 belongs to host H1.
     * Review 50 (the filtered node) belongs to host H2 (unauthorized for H1).
     * Original rewrite for H1 returns {User 100}, mutated returns {User 100, User 200}.
     */
    @Test
    fun mutatedQueryDetectsLeakForReviewFilteredUserReturned() {
        val fixture = createFuzzerTestFixture(withAstReturnNode = true)

        val originalQuery = "MATCH (r:Review)--(u:User) WHERE r.id = 1 RETURN u"
        val mutatedQuery = "MATCH (r:Review)--(u:User) WHERE r.id <> 1 RETURN u"
        val userNode100 = mockNode("User", "100")
        val userNode200 = mockNode("User", "200")
        val reviewNode50 = mockNode("Review", "50")

        // Original query returns User 100
        val originalResult = mockResult(listOf(mockRecord("u" to userNode100)))
        whenever(fixture.session.run(eq(originalQuery), any<TransactionConfig>()))
            .thenReturn(originalResult)

        populateCache(fixture,
            reviewToHost = mapOf("50" to "H2"),
            userToHosts = mapOf("100" to setOf("H1"))
        )

        // Render calls for INDIRECT_REVIEW_FILTERED_USER_RETURNED:
        // 1: prepareQueries rewrite → "PREP_REWRITTEN"
        // 2: checkPerHostCorrectnessForUsers rewrite(query,H1) → "HOST_USER_CHECK"
        // 3: checkMutatedQueryLeaks rewrite(mutated,"0") → "MUT_NONEXIST"
        // 4: addVariablesToReturn render → "MODIFIED_QUERY"
        // 5: rewrite(original,H1) → "ORIG_HOST"
        // 6: rewrite(mutated,H1) → "MUT_HOST"
        // 7: getFilteredNodesFromRewritten addVariablesToReturn(ORIG_HOST) → "ORIG_HOST_FILTERED"
        // 8: getFilteredNodesFromRewritten addVariablesToReturn(MUT_HOST) → "MUT_HOST_FILTERED"
        // Note: checkPerHostCorrectnessForReviews has no reviews → no render call
        whenever(fixture.unparser.render(any())).thenReturn(
            "PREP_REWRITTEN",
            "HOST_USER_CHECK",
            "MUT_NONEXIST",
            "MODIFIED_QUERY",
            "ORIG_HOST",
            "MUT_HOST",
            "ORIG_HOST_FILTERED",
            "MUT_HOST_FILTERED"
        )

        // Pre-create all mock results
        val emptyResult = mockResult()
        val user100Result = mockResult(listOf(mockRecord("u" to userNode100)))
        val review50Result = mockResult(listOf(mockRecord("r" to reviewNode50)))
        val user100And200Result = mockResult(listOf(
            mockRecord("u" to userNode100),
            mockRecord("u" to userNode200)
        ))

        whenever(fixture.session.run(eq("PREP_REWRITTEN"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("HOST_USER_CHECK"), any<TransactionConfig>()))
            .thenReturn(user100Result)
        whenever(fixture.session.run(eq("MUT_NONEXIST"), any<TransactionConfig>()))
            .thenReturn(emptyResult)
        whenever(fixture.session.run(eq("MODIFIED_QUERY"), any<TransactionConfig>()))
            .thenReturn(review50Result)
        whenever(fixture.session.run(eq("ORIG_HOST"), any<TransactionConfig>()))
            .thenReturn(user100Result)
        // MUT_HOST: {User 100, User 200} → different!
        whenever(fixture.session.run(eq("MUT_HOST"), any<TransactionConfig>()))
            .thenReturn(user100And200Result)
        // Rewritten filtered nodes: Review 50 belongs to H2, unauthorized for H1
        whenever(fixture.session.run(eq("ORIG_HOST_FILTERED"), any<TransactionConfig>()))
            .thenReturn(review50Result)
        whenever(fixture.session.run(eq("MUT_HOST_FILTERED"), any<TransactionConfig>()))
            .thenReturn(review50Result)

        val metrics = FuzzMetrics(
            labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
            filteredVariables = setOf("r"),
            returnedVariables = setOf("u")
        )
        val fuzzItem = FuzzItem(originalQuery, mutatedQuery, metrics)

        val ctx = fixture.fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

        assertTrue(ctx.errors.any { it.contains("Indirect access violation") },
            "Differing results must trigger indirect access violation. Errors: ${ctx.errors}")
    }
}
