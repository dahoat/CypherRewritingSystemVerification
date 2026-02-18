package at.daho.cypherrewriting.cypherverificatorairbnb

import at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer.IdentifyReviewAuthorFuzzer
import at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer.ReviewOwnershipFuzzer
import at.daho.cypherrewriting.verification.FuzzItem
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstInternalNode
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstType
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.Detection
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.PermissionDetector
import at.jku.faw.symspace.cypherrewriter.core.cypher.enforcer.CypherEnforcer
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import org.mockito.kotlin.*
import org.neo4j.driver.Record
import org.neo4j.driver.Result
import org.neo4j.driver.Session
import org.neo4j.driver.TransactionConfig
import org.neo4j.driver.Value
import org.neo4j.driver.internal.types.InternalTypeSystem
import org.neo4j.driver.types.Node
import java.util.concurrent.atomic.AtomicInteger

/*
 * Shared test infrastructure for fuzzer tests.
 * This file was generated using AI tools (Claude Code).
 */

private val NODE_TYPE = InternalTypeSystem.TYPE_SYSTEM.NODE()

fun mockNode(label: String, id: String): Node {
    val idValue = mock<Value> { on { toString() } doReturn id }
    return mock<Node> {
        on { labels() } doReturn listOf(label)
        on { get("id") } doReturn idValue
    }
}

fun mockNodeValue(node: Node): Value = mock<Value> {
    on { type() } doReturn NODE_TYPE
    on { asNode() } doReturn node
}

fun mockRecord(vararg entries: Pair<String, Node>): Record {
    val record = mock<Record>()
    whenever(record.keys()).thenReturn(entries.map { it.first })
    for ((key, node) in entries) {
        val value = mockNodeValue(node)
        whenever(record.get(key)).thenReturn(value)
    }
    return record
}

fun mockResult(records: List<Record> = emptyList(), keys: List<String> = listOf("r", "u")): Result =
    mock<Result> {
        on { list() } doReturn records
        on { keys() } doReturn keys
    }

fun mockBulkRecord(vararg entries: Pair<String, String>): Record {
    val record = mock<Record>()
    for ((key, value) in entries) {
        val mockValue = mock<Value> { on { toString() } doReturn value }
        whenever(record[key]).thenReturn(mockValue)
    }
    return record
}

const val BULK_QUERY_REVIEWS =
    "MATCH (r:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(h:Host) RETURN r.id as reviewId, h.id as hostId"
const val BULK_QUERY_USERS =
    "MATCH (u:User)-[:WROTE]->(r:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(h:Host) RETURN u.id as userId, h.id as hostId"
const val BULK_QUERY_USER_FOR_REVIEW =
    "MATCH (u:User)-[:WROTE]->(r:Review) RETURN u.id as userId, r.id as reviewId"

/**
 * Creates a standard set of mocked dependencies for fuzzer tests.
 *
 * @param withDetections if true, detector returns one detection; if false, returns empty list
 * @param detectionCount number of detections to return (only used when withDetections is true)
 * @param withAstReturnNode if true, parser returns a real AstInternalNode with a RETURN child
 *   (needed for tests that exercise addVariablesToReturn). If false, uses a simple mock.
 */
fun createMockedDependencies(
    withDetections: Boolean = true,
    detectionCount: Int = 1,
    withAstReturnNode: Boolean = false
): MockedDependencies {
    val sessionBean: SessionBean = mock()
    val session: Session = mock()
    val parser: CypherRewritingParser = mock()
    val detector: PermissionDetector = mock()
    val enforcer: CypherEnforcer = mock()
    val unparser: CypherRewritingUnparser = mock()

    whenever(sessionBean.session()).thenReturn(session)

    val mockAst: AstInternalNode = if (withAstReturnNode) {
        val returnNode = AstInternalNode(AstType.RETURN)
        AstInternalNode(AstType.QUERY).also { it.elements.add(returnNode) }
    } else {
        mock<AstInternalNode>()
    }
    whenever(parser.parse(any<String>())).thenReturn(mockAst)

    if (withDetections) {
        val detections = (1..detectionCount).map { mock<Detection>() }
        whenever(detector.process(any())).thenReturn(detections)
    } else {
        whenever(detector.process(any())).thenReturn(emptyList())
    }

    whenever(unparser.render(any())).thenReturn("REWRITTEN_QUERY")

    val emptyResult = mockResult()
    whenever(session.run(any<String>(), any<TransactionConfig>())).thenReturn(emptyResult)
    whenever(session.run(any<String>(), any<Map<String, Any>>(), any<TransactionConfig>())).thenReturn(emptyResult)

    return MockedDependencies(sessionBean, session, parser, detector, enforcer, unparser)
}

data class MockedDependencies(
    val sessionBean: SessionBean,
    val session: Session,
    val parser: CypherRewritingParser,
    val detector: PermissionDetector,
    val enforcer: CypherEnforcer,
    val unparser: CypherRewritingUnparser
)

// ========================================================================
// IdentifyReviewAuthorFuzzer test support
// ========================================================================

/**
 * Subclass that exposes protected methods for testing and suppresses file reporting.
 */
class TestableIdentifyReviewAuthorFuzzer(
    sessionBean: SessionBean,
    parser: CypherRewritingParser,
    detector: PermissionDetector,
    enforcer: CypherEnforcer,
    unparser: CypherRewritingUnparser
) : IdentifyReviewAuthorFuzzer(sessionBean, parser, detector, enforcer, unparser) {
    override val reportDirSuffix: String? get() = null

    public override fun doExecuteFuzzRun(
        fuzzItem: FuzzItem,
        iteration: Int,
        relevantCount: AtomicInteger
    ) = super.doExecuteFuzzRun(fuzzItem, iteration, relevantCount)

    public override fun preCacheData(session: Session) = super.preCacheData(session)
}

/**
 * Holds all mocked dependencies for an IdentifyReviewAuthorFuzzer test.
 */
data class FuzzerTestFixture(
    val sessionBean: SessionBean,
    val session: Session,
    val parser: CypherRewritingParser,
    val detector: PermissionDetector,
    val enforcer: CypherEnforcer,
    val unparser: CypherRewritingUnparser,
    val fuzzer: TestableIdentifyReviewAuthorFuzzer
)

/**
 * Creates a standard test fixture with all dependencies mocked.
 *
 * @param withDetections if true, detector returns one detection; if false, returns empty list
 * @param withAstReturnNode if true, parser returns a real AstInternalNode with a RETURN child
 *   (needed for tests that exercise addVariablesToReturn). If false, uses a simple mock.
 */
fun createFuzzerTestFixture(
    withDetections: Boolean = true,
    withAstReturnNode: Boolean = false
): FuzzerTestFixture {
    val deps = createMockedDependencies(withDetections = withDetections, withAstReturnNode = withAstReturnNode)
    val fuzzer = TestableIdentifyReviewAuthorFuzzer(
        deps.sessionBean, deps.parser, deps.detector, deps.enforcer, deps.unparser
    )
    return FuzzerTestFixture(
        deps.sessionBean, deps.session, deps.parser, deps.detector, deps.enforcer, deps.unparser, fuzzer
    )
}

/**
 * Pre-populates the IdentifyReviewAuthorFuzzer's caches by mocking bulk query results.
 */
fun populateCache(
    fixture: FuzzerTestFixture,
    reviewToHost: Map<String, String> = emptyMap(),
    userToHosts: Map<String, Set<String>> = emptyMap()
) {
    val reviewRecords = reviewToHost.map { (reviewId, hostId) ->
        mockBulkRecord("reviewId" to reviewId, "hostId" to hostId)
    }
    val reviewResult = mockResult(reviewRecords)

    val userRecords = userToHosts.flatMap { (userId, hostIds) ->
        hostIds.map { hostId -> mockBulkRecord("userId" to userId, "hostId" to hostId) }
    }
    val userResult = mockResult(userRecords)

    whenever(fixture.session.run(eq(BULK_QUERY_REVIEWS))).thenReturn(reviewResult)
    whenever(fixture.session.run(eq(BULK_QUERY_USERS))).thenReturn(userResult)

    fixture.fuzzer.preCacheData(fixture.session)
}

// ========================================================================
// ReviewOwnershipFuzzer test support
// ========================================================================

/**
 * Subclass that exposes protected methods for testing and suppresses file reporting.
 */
class TestableReviewOwnershipFuzzer(
    sessionBean: SessionBean,
    parser: CypherRewritingParser,
    detector: PermissionDetector,
    enforcer: CypherEnforcer,
    unparser: CypherRewritingUnparser
) : ReviewOwnershipFuzzer(sessionBean, parser, detector, enforcer, unparser) {
    override val reportDirSuffix: String? get() = null

    public override fun doExecuteFuzzRun(
        fuzzItem: FuzzItem,
        iteration: Int,
        relevantCount: AtomicInteger
    ) = super.doExecuteFuzzRun(fuzzItem, iteration, relevantCount)

    public override fun preCacheData(session: Session) = super.preCacheData(session)
}

data class ReviewOwnershipTestFixture(
    val sessionBean: SessionBean,
    val session: Session,
    val parser: CypherRewritingParser,
    val detector: PermissionDetector,
    val enforcer: CypherEnforcer,
    val unparser: CypherRewritingUnparser,
    val fuzzer: TestableReviewOwnershipFuzzer
)

/**
 * Creates a test fixture for ReviewOwnershipFuzzer.
 *
 * @param withDetections if true, detector returns detections
 * @param detectionCount number of detections (for testing multi-detection scenarios)
 */
fun createReviewOwnershipTestFixture(
    withDetections: Boolean = true,
    detectionCount: Int = 1
): ReviewOwnershipTestFixture {
    val deps = createMockedDependencies(withDetections = withDetections, detectionCount = detectionCount)
    val fuzzer = TestableReviewOwnershipFuzzer(
        deps.sessionBean, deps.parser, deps.detector, deps.enforcer, deps.unparser
    )
    return ReviewOwnershipTestFixture(
        deps.sessionBean, deps.session, deps.parser, deps.detector, deps.enforcer, deps.unparser, fuzzer
    )
}

/**
 * Pre-populates the ReviewOwnershipFuzzer's cache by mocking bulk query results.
 */
fun populateReviewOwnershipCache(
    fixture: ReviewOwnershipTestFixture,
    reviewToUser: Map<String, String> = emptyMap()
) {
    val records = reviewToUser.map { (reviewId, userId) ->
        mockBulkRecord("userId" to userId, "reviewId" to reviewId)
    }
    val result = mockResult(records)

    whenever(fixture.session.run(eq(BULK_QUERY_USER_FOR_REVIEW))).thenReturn(result)

    fixture.fuzzer.preCacheData(fixture.session)
}
