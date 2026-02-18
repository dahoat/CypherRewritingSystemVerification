package at.daho.cypherrewriting.cypherverificatorairbnb

import at.daho.cypherrewriting.verification.FuzzItem
import at.daho.cypherrewriting.verification.FuzzMetrics
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.PermissionDetector
import at.jku.faw.symspace.cypherrewriter.core.cypher.enforcer.CypherEnforcer
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import org.neo4j.driver.Session
import org.neo4j.driver.TransactionConfig
import java.util.concurrent.atomic.AtomicInteger

/*
 * This test class was generated using AI tools (Claude Code)
 *
 * Tests for IdentifyReviewAuthorFuzzer: FuzzMetrics classification logic and
 * doExecuteFuzzRun integration paths via mocked dependencies.
 */
class IdentifyReviewAuthorFuzzerTest {

    // =========================================================================
    // FuzzMetrics Classification Tests (pure logic, no mocks)
    // =========================================================================

    @Nested
    inner class FuzzMetricsClassificationTests {

        /**
         * Mirrors the classification logic in IdentifyReviewAuthorFuzzer.doIndirectAccessChecks:
         * User variable is filtered but NOT returned, and Review variable IS returned.
         */
        private fun isIndirectAccessWithUserFilteredAndReviewReturned(metrics: FuzzMetrics): Boolean {
            val reviewVars = metrics.variablesWithLabel("Review")
            val userVars = metrics.variablesWithLabel("User")
            return (userVars intersect metrics.filteredVariables).isNotEmpty() &&
                    (userVars intersect metrics.returnedVariables).isEmpty() &&
                    (reviewVars intersect metrics.returnedVariables).isNotEmpty()
        }

        /**
         * Mirrors the classification logic in IdentifyReviewAuthorFuzzer.doIndirectAccessChecks:
         * Review variable is filtered but NOT returned, and User variable IS returned.
         */
        private fun isIndirectAccessWithReviewFilteredAndUserReturned(metrics: FuzzMetrics): Boolean {
            val reviewVars = metrics.variablesWithLabel("Review")
            val userVars = metrics.variablesWithLabel("User")
            return (reviewVars intersect metrics.filteredVariables).isNotEmpty() &&
                    (reviewVars intersect metrics.returnedVariables).isEmpty() &&
                    (userVars intersect metrics.returnedVariables).isNotEmpty()
        }

        @Test
        fun userFilteredNotReturnedReviewReturned() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            assertTrue(isIndirectAccessWithUserFilteredAndReviewReturned(metrics))
            assertFalse(isIndirectAccessWithReviewFilteredAndUserReturned(metrics))
        }

        @Test
        fun reviewFilteredNotReturnedUserReturned() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("r"),
                returnedVariables = setOf("u")
            )
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics))
            assertTrue(isIndirectAccessWithReviewFilteredAndUserReturned(metrics))
        }

        @Test
        fun bothReturnedDirectAccess() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = emptySet(),
                returnedVariables = setOf("u", "r")
            )
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics))
            assertFalse(isIndirectAccessWithReviewFilteredAndUserReturned(metrics))
        }

        @Test
        fun neitherReturnedNorFiltered() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = emptySet(),
                returnedVariables = emptySet()
            )
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics))
            assertFalse(isIndirectAccessWithReviewFilteredAndUserReturned(metrics))
        }

        /**
         * Traversal access: User is filtered AND returned, Review is neither.
         * E.g. MATCH (u:User)-[:WROTE]->(r:Review) WHERE u.id = X RETURN u
         * This is safe — no Review data leaks.
         */
        private fun isTraversalAccess(metrics: FuzzMetrics): Boolean {
            val userVars = metrics.variablesWithLabel("User")
            val reviewVars = metrics.variablesWithLabel("Review")
            return (userVars intersect metrics.filteredVariables).isNotEmpty() &&
                    (userVars intersect metrics.returnedVariables).isNotEmpty() &&
                    (reviewVars intersect metrics.filteredVariables).isEmpty() &&
                    (reviewVars intersect metrics.returnedVariables).isEmpty()
        }

        @Test
        fun traversalAccessUserFilteredAndReturnedReviewNeither() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("u")
            )
            assertTrue(isTraversalAccess(metrics),
                "User filtered+returned, Review neither → traversal access")
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics))
            assertFalse(isIndirectAccessWithReviewFilteredAndUserReturned(metrics))
        }

        @Test
        fun traversalAccessNotWhenReviewReturned() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("u", "r")
            )
            assertFalse(isTraversalAccess(metrics),
                "Review is returned → not traversal access")
        }

        @Test
        fun traversalAccessNotWhenReviewFiltered() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u", "r"),
                returnedVariables = setOf("u")
            )
            assertFalse(isTraversalAccess(metrics),
                "Review is filtered → not traversal access")
        }

        @Test
        fun userFilteredAndReturnedReviewReturned() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("u", "r")
            )
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics),
                "User is returned, so this is not an indirect access case")
            assertFalse(isIndirectAccessWithReviewFilteredAndUserReturned(metrics))
        }

        @Test
        fun noReviewOrUserVariables() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("l" to setOf("Listing"), "h" to setOf("Host")),
                filteredVariables = setOf("l"),
                returnedVariables = setOf("h")
            )
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics))
            assertFalse(isIndirectAccessWithReviewFilteredAndUserReturned(metrics))
        }

        @Test
        fun multipleUserVariablesOneFilteredOneReturned() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u1" to setOf("User"), "u2" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u1"),
                returnedVariables = setOf("u2", "r")
            )
            // userVars = {u1, u2}, u2 is in returnedVariables → condition (userVars ∩ returned).isEmpty() fails
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics),
                "u2 is returned, so userVars intersect returnedVariables is not empty")
        }

        @Test
        fun reviewFilteredAndReturnedUserReturned() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("r"),
                returnedVariables = setOf("u", "r")
            )
            assertFalse(isIndirectAccessWithReviewFilteredAndUserReturned(metrics),
                "Review is returned, so this is not an indirect access case for branch 2")
            assertFalse(isIndirectAccessWithUserFilteredAndReviewReturned(metrics))
        }
    }

    // =========================================================================
    // doExecuteFuzzRun Integration Tests (with mocked dependencies)
    // =========================================================================

    @Nested
    inner class DoExecuteFuzzRunTests {

        private lateinit var sessionBean: SessionBean
        private lateinit var session: Session
        private lateinit var parser: CypherRewritingParser
        private lateinit var detector: PermissionDetector
        private lateinit var enforcer: CypherEnforcer
        private lateinit var unparser: CypherRewritingUnparser
        private lateinit var fuzzer: TestableIdentifyReviewAuthorFuzzer

        @BeforeEach
        fun setUp() {
            val fixture = createFuzzerTestFixture()
            sessionBean = fixture.sessionBean
            session = fixture.session
            parser = fixture.parser
            detector = fixture.detector
            enforcer = fixture.enforcer
            unparser = fixture.unparser
            fuzzer = fixture.fuzzer
        }

        // -----------------------------------------------------------------
        // Basic path tests (empty DB results)
        // -----------------------------------------------------------------

        @Test
        fun noReviewUserLabelsNoIndirectAccess() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("l" to setOf("Listing")),
                filteredVariables = emptySet(),
                returnedVariables = setOf("l")
            )
            val fuzzItem = FuzzItem("MATCH (l:Listing) RETURN l", null, metrics)
            val relevantCount = AtomicInteger(0)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            assertNotNull(ctx)
            assertEquals(0, relevantCount.get(), "No Review/User labels means no indirect access")
            assertTrue(ctx.errors.isEmpty())
        }

        @Test
        fun directAccessBothReturnedNoRelevantCountIncrement() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = emptySet(),
                returnedVariables = setOf("u", "r")
            )
            val fuzzItem = FuzzItem("MATCH (r:Review)--(u:User) RETURN r, u", null, metrics)
            val relevantCount = AtomicInteger(0)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            assertNotNull(ctx)
            assertEquals(0, relevantCount.get(), "Direct access should not increment relevantCount")
        }

        @Test
        fun bothIndirectAccessConditionsAreMutuallyExclusive() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf(
                    "u" to setOf("User"),
                    "r" to setOf("Review"),
                    "u2" to setOf("User"),
                    "r2" to setOf("Review")
                ),
                filteredVariables = setOf("u", "r2"),
                returnedVariables = setOf("r", "u2")
            )
            val fuzzItem = FuzzItem("MATCH (r:Review)--(u:User), (r2:Review)--(u2:User) RETURN r, u2", null, metrics)
            val relevantCount = AtomicInteger(0)

            fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            assertEquals(0, relevantCount.get(),
                "Neither indirect access condition should be true when User/Review vars appear in both filtered and returned")
        }

        @Test
        fun mutatedQueryNullSkipsCompareMutatedQuery() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val fuzzItem = FuzzItem("MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r", null, metrics)
            val relevantCount = AtomicInteger(0)

            fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            // prepareQueries: 2 calls (original + rewritten)
            // No compareMutatedQuery since mutatedQuery is null
            verify(session, times(2)).run(any<String>(), any<TransactionConfig>())
        }

        @Test
        fun noIndirectAccessWithMutatedQuerySkipsCompareMutatedQuery() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = emptySet(),
                returnedVariables = setOf("u", "r")
            )
            val mutatedQuery = "MATCH (r:Review)--(u:User) RETURN r, u LIMIT 5"
            val fuzzItem = FuzzItem("MATCH (r:Review)--(u:User) RETURN r, u", mutatedQuery, metrics)
            val relevantCount = AtomicInteger(0)

            fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            verify(session, never()).run(eq(mutatedQuery), any<TransactionConfig>())
        }

        // -----------------------------------------------------------------
        // relevantCount tests (require originalNodes to be non-empty)
        // -----------------------------------------------------------------

        @Test
        fun indirectAccessUserFilteredReviewReturnedWithOriginalNodesIncrementsRelevantCount() {
            val originalQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r"
            val userNode = mockNode("User", "100")
            val originalResult = mockResult(listOf(mockRecord("u" to userNode)))

            whenever(session.run(eq(originalQuery), any<TransactionConfig>())).thenReturn(originalResult)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)
            val relevantCount = AtomicInteger(0)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            assertNotNull(ctx)
            assertEquals(1, relevantCount.get(), "Indirect access with non-empty originalNodes should increment relevantCount")
        }

        @Test
        fun indirectAccessReviewFilteredUserReturnedWithOriginalNodesIncrementsRelevantCount() {
            val originalQuery = "MATCH (r:Review)--(u:User) WHERE r.id = 1 RETURN u"
            val userNode = mockNode("User", "100")
            val originalResult = mockResult(listOf(mockRecord("u" to userNode)))

            whenever(session.run(eq(originalQuery), any<TransactionConfig>())).thenReturn(originalResult)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("r"),
                returnedVariables = setOf("u")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)
            val relevantCount = AtomicInteger(0)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            assertNotNull(ctx)
            assertEquals(1, relevantCount.get(), "Indirect access with non-empty originalNodes should increment relevantCount")
        }

        @Test
        fun indirectAccessWithEmptyOriginalNodesDoesNotIncrementRelevantCount() {
            // Indirect access pattern but DB returns no User nodes → relevantCount stays 0
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val fuzzItem = FuzzItem("MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r", null, metrics)
            val relevantCount = AtomicInteger(0)

            fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            assertEquals(0, relevantCount.get(),
                "Indirect access with empty originalNodes should NOT increment relevantCount")
        }

        @Test
        fun mutatedQueryWithIndirectAccessTriggersCompareMutatedQuery() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val mutatedQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 999 RETURN r"
            val fuzzItem = FuzzItem("MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r", mutatedQuery, metrics)
            val relevantCount = AtomicInteger(0)

            fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            verify(parser, atLeast(1)).parse(eq(mutatedQuery))
        }

        @Test
        fun traversalAccessSkipsUnauthorizedUserCheck() {
            // Traversal access: MATCH (u:User)--(r:Review) WHERE u.id = X RETURN u
            // User is filtered+returned, Review is neither → safe, no false positive
            val originalQuery = "MATCH (u:User)--(r:Review) WHERE u.id = 1 RETURN u"
            val userNode = mockNode("User", "100")

            // Both original and rewritten return the same user
            val result = mockResult(listOf(mockRecord("u" to userNode)))
            whenever(session.run(any<String>(), any<TransactionConfig>())).thenReturn(result)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("u")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

            assertTrue(ctx.errors.isEmpty(),
                "Traversal access should not produce unauthorized-user errors. Errors: ${ctx.errors}")
        }

        @Test
        fun mutatedQueryWithReviewFilteredUserReturnedTriggersCompareMutatedQuery() {
            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("r"),
                returnedVariables = setOf("u")
            )
            val mutatedQuery = "MATCH (r:Review)--(u:User) WHERE r.id = 999 RETURN u"
            val fuzzItem = FuzzItem("MATCH (r:Review)--(u:User) WHERE r.id = 1 RETURN u", mutatedQuery, metrics)
            val relevantCount = AtomicInteger(0)

            fuzzer.doExecuteFuzzRun(fuzzItem, 0, relevantCount)

            verify(parser, atLeast(1)).parse(eq(mutatedQuery))
        }
    }

    // =========================================================================
    // Error Detection Tests: verifies that an ineffective filter (e.g. "or true")
    // is correctly detected as an error by the fuzzer
    // =========================================================================

    @Nested
    inner class IneffectiveFilterDetectionTests {

        private lateinit var sessionBean: SessionBean
        private lateinit var session: Session
        private lateinit var parser: CypherRewritingParser
        private lateinit var detector: PermissionDetector
        private lateinit var enforcer: CypherEnforcer
        private lateinit var unparser: CypherRewritingUnparser
        private lateinit var fuzzer: TestableIdentifyReviewAuthorFuzzer

        @BeforeEach
        fun setUp() {
            val fixture = createFuzzerTestFixture()
            sessionBean = fixture.sessionBean
            session = fixture.session
            parser = fixture.parser
            detector = fixture.detector
            enforcer = fixture.enforcer
            unparser = fixture.unparser
            fuzzer = fixture.fuzzer
        }

        /**
         * Simulates "or true" in filter: the rewritten query for a non-existent host
         * still returns Review nodes. checkIndirectAccessWithUserFilteredAndReviewReturned
         * must detect this.
         */
        @Test
        fun indirectAccessDetectsReviewsReturnedForNonExistentHost() {
            val originalQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r"
            val reviewNode = mockNode("Review", "42")

            // Original query returns a Review (normal behavior)
            val originalResult = mockResult(listOf(mockRecord("r" to reviewNode)))
            whenever(session.run(eq(originalQuery), any<TransactionConfig>())).thenReturn(originalResult)

            // Rewritten query (non-existent host) ALSO returns Reviews → filter is ineffective!
            val rewrittenWithLeakedReviews = mockResult(listOf(mockRecord("r" to reviewNode)))
            whenever(session.run(eq("REWRITTEN_QUERY"), any<TransactionConfig>())).thenReturn(rewrittenWithLeakedReviews)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

            assertTrue(ctx.errors.any { it.contains("unauthorized reviews") },
                "Must detect that rewritten query leaks Review nodes for non-existent host. Errors: ${ctx.errors}")
        }

        /**
         * Direct access: the rewritten query (non-existent host) returns MORE User nodes
         * than the original. This indicates the filter is producing spurious results.
         */
        @Test
        fun directAccessDetectsRewrittenHasMoreUserNodesThanOriginal() {
            val originalQuery = "MATCH (r:Review)--(u:User) RETURN r, u"
            val userNode1 = mockNode("User", "100")
            val userNode2 = mockNode("User", "200")

            // Original: returns only user 100
            val originalResult = mockResult(listOf(mockRecord("u" to userNode1)))
            whenever(session.run(eq(originalQuery), any<TransactionConfig>())).thenReturn(originalResult)

            // Rewritten (non-existent host): returns users 100 AND 200 → filter adds spurious results
            val rewrittenResult = mockResult(listOf(
                mockRecord("u" to userNode1),
                mockRecord("u" to userNode2)
            ))
            whenever(session.run(eq("REWRITTEN_QUERY"), any<TransactionConfig>())).thenReturn(rewrittenResult)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = emptySet(),
                returnedVariables = setOf("u", "r")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

            assertTrue(ctx.errors.any { it.contains("rewritten query contains more nodes than original") },
                "Must detect that rewritten query contains more nodes. Errors: ${ctx.errors}")
        }

        /**
         * Simulates "or true" in filter on a mutated query: rewriting the mutated query
         * with a non-existent host still returns nodes (verifyMutatedQueryDoesNotReturnResultsForNonexistentHost).
         */
        @Test
        fun mutatedQueryDetectsNodesReturnedForNonExistentHost() {
            val originalQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r"
            val mutatedQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 999 RETURN r"
            val reviewNode = mockNode("Review", "77")

            // The rewritten mutated query (non-existent host) returns Review nodes → filter is broken
            // Both "REWRITTEN_QUERY" (from rewrite of original) and "REWRITTEN_QUERY" (from rewrite of mutated)
            // use the same mock render output, so all rewritten queries return this:
            val resultWithNodes = mockResult(listOf(mockRecord("r" to reviewNode)))
            whenever(session.run(eq("REWRITTEN_QUERY"), any<TransactionConfig>())).thenReturn(resultWithNodes)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val fuzzItem = FuzzItem(originalQuery, mutatedQuery, metrics)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

            assertTrue(ctx.errors.any { it.contains("Mutated query returns nodes for non-existent host") },
                "Must detect that mutated rewritten query leaks nodes for non-existent host. Errors: ${ctx.errors}")
        }

        /**
         * Direct access: for each original User, the fuzzer checks results rewritten
         * for that User's host. If unauthorized Users appear → error.
         * Simulates: User 100 reviewed host "H1". Rewriting for host "H1" returns
         * User 200 who did NOT review host "H1" → unauthorized access.
         */
        @Test
        fun directAccessDetectsUnauthorizedUserForValidHost() {
            val originalQuery = "MATCH (r:Review)--(u:User) RETURN r, u"
            val userNode100 = mockNode("User", "100")
            val userNode200 = mockNode("User", "200")
            val reviewNode10 = mockNode("Review", "10")

            // Original query returns User 100 and Review 10
            val originalResult = mockResult(listOf(mockRecord("u" to userNode100, "r" to reviewNode10)))
            whenever(session.run(eq(originalQuery), any<TransactionConfig>())).thenReturn(originalResult)

            populateCache(
                FuzzerTestFixture(sessionBean, session, parser, detector, enforcer, unparser, fuzzer),
                reviewToHost = mapOf("10" to "H1"),
                userToHosts = mapOf("100" to setOf("H1"), "200" to setOf("H2"))
            )

            // Rewriting for host "H1" returns User 200 (who didn't review H1)
            val rewrittenForHostResult = mockResult(listOf(mockRecord("u" to userNode200)))
            // rewrite() renders to "REWRITTEN_QUERY" for all inputs
            whenever(session.run(eq("REWRITTEN_QUERY"), any<TransactionConfig>())).thenReturn(rewrittenForHostResult)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = emptySet(),
                returnedVariables = setOf("u", "r")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

            assertTrue(ctx.errors.any { it.contains("missing authorized users") || it.contains("contains users not in original") },
                "Must detect missing authorized users or added users in rewritten query for valid host. Errors: ${ctx.errors}")
        }

        /**
         * Indirect access: for each original Review, the fuzzer looks up its host
         * and checks if the rewritten query for that host returns unauthorized Reviews.
         * Simulates: Review 42 belongs to host "H1". Rewriting for host "H1" returns
         * Review 99 which does NOT belong to host "H1" → unauthorized access.
         */
        @Test
        fun indirectAccessDetectsUnauthorizedReviewForValidHost() {
            val originalQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r"
            val reviewNode42 = mockNode("Review", "42")
            val reviewNode99 = mockNode("Review", "99")

            // Original query returns Review 42
            val originalResult = mockResult(listOf(mockRecord("r" to reviewNode42)))
            whenever(session.run(eq(originalQuery), any<TransactionConfig>())).thenReturn(originalResult)

            populateCache(
                FuzzerTestFixture(sessionBean, session, parser, detector, enforcer, unparser, fuzzer),
                reviewToHost = mapOf("42" to "H1", "99" to "H2")
            )

            // Rewriting for host "H1" returns Review 99
            val rewrittenForHostResult = mockResult(listOf(mockRecord("r" to reviewNode99)))
            whenever(session.run(eq("REWRITTEN_QUERY"), any<TransactionConfig>())).thenReturn(rewrittenForHostResult)

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

            assertTrue(ctx.errors.any { it.contains("missing authorized reviews") || it.contains("contains reviews not in original") },
                "Must detect missing authorized reviews or added reviews in rewritten query for valid host. Errors: ${ctx.errors}")
        }

        /**
         * Negative test: when the filter works correctly, no errors should be registered.
         * The rewritten query for non-existent host returns nothing.
         */
        @Test
        fun effectiveFilterProducesNoErrors() {
            val originalQuery = "MATCH (r:Review)--(u:User) WHERE u.id = 1 RETURN r"
            val reviewNode = mockNode("Review", "42")

            // Original query returns Review nodes (normal behavior)
            val originalResult = mockResult(listOf(mockRecord("r" to reviewNode)))
            whenever(session.run(eq(originalQuery), any<TransactionConfig>())).thenReturn(originalResult)

            // Rewritten query (non-existent host) returns NOTHING → filter works!
            // Second call (valid host H1) returns the authorized review "42"
            val emptyRewrittenResult = mockResult()
            val rewrittenForValidHostResult = mockResult(listOf(mockRecord("r" to reviewNode)))
            whenever(session.run(eq("REWRITTEN_QUERY"), any<TransactionConfig>()))
                .thenReturn(emptyRewrittenResult)
                .thenReturn(rewrittenForValidHostResult)

            populateCache(
                FuzzerTestFixture(sessionBean, session, parser, detector, enforcer, unparser, fuzzer),
                reviewToHost = mapOf("42" to "H1")
            )

            val metrics = FuzzMetrics(
                labeledVariables = mapOf("u" to setOf("User"), "r" to setOf("Review")),
                filteredVariables = setOf("u"),
                returnedVariables = setOf("r")
            )
            val fuzzItem = FuzzItem(originalQuery, null, metrics)

            val ctx = fuzzer.doExecuteFuzzRun(fuzzItem, 0, AtomicInteger(0))

            assertTrue(ctx.errors.isEmpty(),
                "Effective filter should produce no errors. Errors: ${ctx.errors}")
        }
    }
}
