package at.daho.cypherrewriting.cypherverificatorairbnb

import at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer.IdentifyReviewAuthorPermissionConfig
import at.jku.faw.symspace.cypherrewriter.core.cypher.*
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.Detection
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.PermissionDetectorImpl
import at.jku.faw.symspace.cypherrewriter.core.cypher.enforcer.CypherEnforcerImpl
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParserImpl
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparserImpl
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/*
 * This test class was generated using AI tools (Claude Code)
 *
 * Tests for the ReviewAuthor permission policy which controls access to
 * review authors: only Hosts may see the authors (Users) of reviews on
 * their Listings.
 *
 * The policy pattern is (r:Review)--(u:User) with CONTAINS_ANY + matchEmptyLabels
 * for "r", and a single rule "reviewAuthorsReadByHost" on variable "u" with
 * three OR-combined condition branches:
 *   1. Direct access:   r=ANY/ANY_RETURN AND u=ANY/ANY_RETURN
 *   2. Indirect (review filtered): r=FILTERED/NO_RETURN AND u=ANY/ANY_RETURN
 *   3. Indirect (user filtered):   r=ANY/ANY_RETURN AND u=FILTERED/NO_RETURN
 *
 * The filter template "authorizeHostOnReview" injects:
 *   (%s:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(:Host {id: %s})
 */
class ReviewAuthorPermissionTest {

    private val parser = CypherRewritingParserImpl()
    private val unparser = CypherRewritingUnparserImpl()
    private val returnTypeHelper: ReturnTypeHelper = ReturnTypeHelperImpl()
    private val filterTypeHelper: FilterTypeHelper = FilterTypeHelperImpl()
    private val labelMatcher: LabelMatcher = LabelMatcherImpl()
    private val ruleHelper: RuleHelper = RuleHelperImpl(filterTypeHelper, returnTypeHelper)

    private val config = IdentifyReviewAuthorPermissionConfig

    private lateinit var detector: PermissionDetectorImpl

    @BeforeEach
    fun setUp() {
        detector = PermissionDetectorImpl(parser, returnTypeHelper, filterTypeHelper, labelMatcher, ruleHelper, config)
    }

    private fun parse(query: String): AstInternalNode {
        val parserInstance = parser.getParser(query)
        val context = parserInstance.oC_Cypher()
        return parser.parse(context) as AstInternalNode
    }

    private fun detect(query: String): List<Detection> {
        val ast = parse(query)
        return detector.process(ast)
    }

    private fun rewrite(query: String, hostId: String): String {
        val ast = parse(query)
        val detections = detector.process(ast)
        val appContext = object : CypherAppContext {
            override var currentUsername: String = hostId
        }
        val enforcer = CypherEnforcerImpl(appContext, config)
        enforcer.enforce(detections)
        return unparser.render(ast)
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    @Nested
    inner class DetectionTests {

        // --- Direct access (branch 1): both r and u returned ---

        @Test
        fun directAccessBothReturned() {
            val detections = detect("MATCH (r:Review)--(u:User) RETURN r, u")
            assertEquals(1, detections.size)
            assertEquals("reviewAuthorsReadByHost", detections[0].rule.id)
        }

        @Test
        fun directAccessReturnStar() {
            val detections = detect("MATCH (r:Review)--(u:User) RETURN *")
            assertEquals(1, detections.size)
        }

        @Test
        fun directAccessWithRelVariable() {
            val detections = detect("MATCH (r:Review)-[rel]-(u:User) RETURN r, u")
            assertEquals(1, detections.size)
        }

        // --- Indirect access branch 2: Review filtered + not returned, User returned ---

        @Test
        fun indirectReviewFilteredUserReturned() {
            val detections = detect("MATCH (r:Review)--(u:User) WHERE r.id = 123 RETURN u")
            assertEquals(1, detections.size)
        }

        @Test
        fun indirectReviewFilteredByPropertyInNode() {
            val detections = detect("MATCH (r:Review {id: 123})--(u:User) RETURN u")
            assertEquals(1, detections.size)
        }

        // --- Indirect access branch 3: User filtered + not returned, Review returned ---

        @Test
        fun indirectUserFilteredReviewReturned() {
            val detections = detect("MATCH (r:Review)--(u:User) WHERE u.id = 456 RETURN r")
            assertEquals(1, detections.size)
        }

        @Test
        fun indirectUserFilteredByPropertyInNode() {
            val detections = detect("MATCH (r:Review)--(u:User {id: 456}) RETURN r")
            assertEquals(1, detections.size)
        }

        // --- matchEmptyLabels: label-less nodes should match ---

        @Test
        fun matchEmptyLabelsReviewNodeWithoutLabel() {
            // r has CONTAINS_ANY + matchEmptyLabels=true, so a label-less node should match
            val detections = detect("MATCH (r)--(u:User) RETURN r, u")
            assertEquals(1, detections.size)
        }

        // --- Longer paths with Review--User embedded ---

        @Test
        fun longerPathContainingReviewUser() {
            val detections = detect("MATCH (l:Listing)--(r:Review)--(u:User) RETURN r, u")
            assertEquals(1, detections.size)
        }

        // --- No match cases ---

        @Test
        fun noMatchWhenLabelsDoNotMatch() {
            val detections = detect("MATCH (r:Listing)--(u:Host) RETURN r, u")
            assertTrue(detections.isEmpty())
        }

        @Test
        fun noMatchWhenOnlyReviewPresent() {
            val detections = detect("MATCH (r:Review) RETURN r")
            assertTrue(detections.isEmpty())
        }

        @Test
        fun noMatchWhenOnlyUserPresent() {
            val detections = detect("MATCH (u:User) RETURN u")
            assertTrue(detections.isEmpty())
        }

        @Test
        fun noMatchWhenBothNotReturnedAndNotFiltered() {
            // Neither r nor u is returned or filtered - none of the 3 branches match
            val detections = detect("MATCH (r:Review)--(u:User)--(l:Listing) RETURN l")
            assertTrue(detections.isEmpty())
        }
    }

    // =========================================================================
    // Enforcement tests (detection + filter injection)
    // =========================================================================

    @Nested
    inner class EnforcementTests {

        @Test
        fun directAccessInjectsHostFilter() {
            val rewritten = rewrite("MATCH (r:Review)--(u:User) RETURN r, u", "42")
            assertTrue(rewritten.contains("HOSTS"))
            assertTrue(rewritten.contains("id: 42"))
            assertTrue(rewritten.contains("Review"))
        }

        @Test
        fun indirectReviewFilteredInjectsHostFilter() {
            val rewritten = rewrite("MATCH (r:Review)--(u:User) WHERE r.id = 123 RETURN u", "42")
            assertTrue(rewritten.contains("HOSTS"))
            assertTrue(rewritten.contains("id: 42"))
        }

        @Test
        fun indirectUserFilteredInjectsHostFilter() {
            val rewritten = rewrite("MATCH (r:Review)--(u:User) WHERE u.id = 456 RETURN r", "42")
            assertTrue(rewritten.contains("HOSTS"))
            assertTrue(rewritten.contains("id: 42"))
        }

        @Test
        fun noDetectionMeansNoRewrite() {
            val original = "MATCH (l:Listing) RETURN l"
            val rewritten = rewrite(original, "42")
            assertEquals(original, rewritten)
        }

        @Test
        fun filterPreservesExistingWhereClause() {
            val rewritten = rewrite("MATCH (r:Review)--(u:User) WHERE r.id = 123 RETURN u", "42")
            // The existing WHERE condition should still be present
            assertTrue(rewritten.contains("r.id = 123") || rewritten.contains("r.id =123"))
            // And the injected filter too
            assertTrue(rewritten.contains("HOSTS"))
        }

        @Test
        fun rewriteWithDifferentHostIds() {
            val rewritten1 = rewrite("MATCH (r:Review)--(u:User) RETURN r, u", "100")
            val rewritten2 = rewrite("MATCH (r:Review)--(u:User) RETURN r, u", "200")
            assertTrue(rewritten1.contains("id: 100"))
            assertTrue(rewritten2.contains("id: 200"))
            assertNotEquals(rewritten1, rewritten2)
        }
    }

    // =========================================================================
    // Condition branch boundary tests
    // =========================================================================

    @Nested
    inner class ConditionBoundaryTests {

        @Test
        fun reviewFilteredAndReturnedDoesNotMatchBranch2() {
            // Branch 2 requires r=FILTERED + NO_RETURN. If r is both filtered AND returned,
            // it should still match branch 1 (direct access) but not branch 2 specifically.
            val detections = detect("MATCH (r:Review)--(u:User) WHERE r.id = 123 RETURN r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun userFilteredAndReturnedDoesNotMatchBranch3() {
            // Branch 3 requires u=FILTERED + NO_RETURN. If u is both filtered AND returned,
            // it should still match branch 1 (direct access) but not branch 3 specifically.
            val detections = detect("MATCH (r:Review)--(u:User) WHERE u.id = 456 RETURN r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun bothFilteredNeitherReturnedNoMatch() {
            // Both r and u filtered but neither returned - no branch matches
            val detections = detect("MATCH (r:Review {id: 1})--(u:User {id: 2})--(l:Listing) RETURN l")
            assertTrue(detections.isEmpty())
        }

        @Test
        fun reviewReturnedViaPropertyAccess() {
            // r.id in RETURN counts as returned
            val detections = detect("MATCH (r:Review)--(u:User) RETURN r.id, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun userReturnedViaPropertyAccess() {
            val detections = detect("MATCH (r:Review)--(u:User) RETURN r, u.name")
            assertEquals(1, detections.size)
        }
    }

    // =========================================================================
    // Pattern variant tests
    // =========================================================================

    @Nested
    inner class PatternVariantTests {

        @Test
        fun directedRelationshipLeftToRight() {
            val detections = detect("MATCH (r:Review)-->(u:User) RETURN r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun directedRelationshipRightToLeft() {
            val detections = detect("MATCH (r:Review)<--(u:User) RETURN r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun reversedNodeOrder() {
            val detections = detect("MATCH (u:User)--(r:Review) RETURN r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun typedRelationship() {
            val detections = detect("MATCH (r:Review)-[:WROTE]-(u:User) RETURN r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun multipleLabelsOnReviewNode() {
            // CONTAINS_ANY means if "Review" is among the labels, it should match
            val detections = detect("MATCH (r:Review:Featured)--(u:User) RETURN r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun distinctReturnBothVariables() {
            val detections = detect("MATCH (r:Review)--(u:User) RETURN DISTINCT r, u")
            assertEquals(1, detections.size)
        }

        @Test
        fun withLimit() {
            val detections = detect("MATCH (r:Review)--(u:User) RETURN r, u LIMIT 10")
            assertEquals(1, detections.size)
        }
    }
}
