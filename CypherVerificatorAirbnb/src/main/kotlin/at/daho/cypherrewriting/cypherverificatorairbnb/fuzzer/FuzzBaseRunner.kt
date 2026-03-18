package at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer

import at.daho.cypherrewriting.cypherverificatorairbnb.SessionBean
import at.daho.cypherrewriting.cypherverificatorairbnb.model.FuzzRunContext
import at.daho.cypherrewriting.cypherverificatorairbnb.model.RewriteResult
import at.daho.cypherrewriting.verification.CypherSchema
import at.daho.cypherrewriting.verification.FuzzGenerator
import at.daho.cypherrewriting.verification.FuzzItem
import at.daho.cypherrewriting.verification.FuzzSettings
import at.daho.cypherrewriting.verification.fuzzSettings
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstInternalNode
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.PermissionDetector
import at.jku.faw.symspace.cypherrewriter.core.cypher.enforcer.CypherEnforcer
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.neo4j.driver.Session
import org.neo4j.driver.Record
import org.neo4j.driver.Result
import org.neo4j.driver.TransactionConfig
import org.neo4j.driver.internal.types.InternalTypeSystem
import org.neo4j.driver.types.Node
import java.io.BufferedWriter
import java.io.FileWriter
import java.io.Writer
import java.nio.file.Paths
import java.time.Duration
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile
import kotlin.io.path.div
import kotlin.io.path.exists

abstract class FuzzBaseRunner(
    protected val sessionBean: SessionBean,
    protected val parser: CypherRewritingParser,
    protected val detector: PermissionDetector,
    protected val enforcer: CypherEnforcer,
    protected val unparser: CypherRewritingUnparser
) {

    protected val transactionConfig: TransactionConfig = TransactionConfig.builder().withTimeout(Duration.ofSeconds(1)).build()
    protected open val statusInterval: Int = 10

    protected fun isNodeWithLabel(key: String, entry: Record, label: String): Boolean {
        if (entry[key].type() == InternalTypeSystem.TYPE_SYSTEM.NODE()) {
            val node = entry[key].asNode()
            return node.labels().contains(label)
        }
        return false
    }

    fun getRelevantNodes(results: List<Record>, relevantLabels: List<String>): List<Node> {
        return results.flatMap { entry ->
            entry.keys()
                .filter { key -> relevantLabels.any { label -> isNodeWithLabel(key, entry, label) } }
                .map { key -> entry[key].asNode() }
        }
    }

    protected fun prepareQueries(fuzzItem: FuzzItem, relevantLabels: List<String>, invalidId: String): FuzzRunContext {
        val session = sessionBean.session()
        val rewrittenCtx = rewrite(fuzzItem.query, invalidId)

        val originalQueryResult = session.run(fuzzItem.query, transactionConfig)
        val originalTuples = originalQueryResult.list()

        val rewrittenQueryResult = session.run(rewrittenCtx.rewrittenQuery, transactionConfig)
        val rewrittenTuples = rewrittenQueryResult.list()

        val originalNodes = getRelevantNodes(originalTuples, relevantLabels).toSet()
        val rewrittenNodes = getRelevantNodes(rewrittenTuples, relevantLabels).toSet()

        return FuzzRunContext(
            session,
            rewrittenCtx.originalQuery,
            originalNodes,
            originalQueryResult,
            originalTuples,
            rewrittenCtx.rewrittenQuery,
            rewrittenNodes,
            rewrittenQueryResult,
            rewrittenTuples,
            rewrittenCtx.detections,
            fuzzItem.metrics,
        )
    }

    protected open fun constructFuzzingSettings(): FuzzSettings = fuzzSettings {
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
            limitProbability = 0.0
            aggregationProbability = 0.0
        }
    }

    protected fun constructSchema(): CypherSchema = CypherSchema {
        val hostNode = cypherNode("Host") {
            property("id", Long::class)
            property("name", String::class)
        }

        val listingNode = cypherNode("Listing") {
            property("id", Long::class)
            property("name", String::class)
        }

        val amenityNode = cypherNode("Amenity") {
            property("name", String::class)
        }

        val reviewNode = cypherNode("Review") {
            property("id", Long::class)
            property("name", String::class)
        }

        val userNode = cypherNode("User") {
            property("id", Long::class)
            property("name", String::class)
        }

        cypherRelationship(hostNode, "HOSTS", listingNode)
        cypherRelationship(listingNode, "HAS", amenityNode)
        cypherRelationship(reviewNode, "REVIEWS", listingNode)
        cypherRelationship(userNode, "WROTE", reviewNode)

        fetchValuesFromDatabase(sessionBean.session())
    }

    protected open fun preCacheData(session: Session) {}

    fun runCoroutineFuzzer() {
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        val i = AtomicInteger(0)
        val relevantCount = AtomicInteger(0)

        val schema = constructSchema()
        val fuzzSettings = constructFuzzingSettings()
        val fuzzGenerator = FuzzGenerator(schema, fuzzSettings)

        sessionBean.session().use { session -> preCacheData(session) }

        runBlocking {
            (1..18).map { threadId ->
                scope.launch {
                    fuzzGenerator.forEach { fuzzItem ->
                        val iteration = i.getAndIncrement()
                        if (iteration % statusInterval == 0) {
                            print("\rAttempt $iteration (${relevantCount.get()} relevant queries)")
                        }
                        executeFuzzRun(fuzzItem, iteration, relevantCount)
                    }
                }
            }.joinAll()
        }
    }

    protected abstract fun doExecuteFuzzRun(fuzzItem: FuzzItem, iteration: Int, relevantCount: AtomicInteger): FuzzRunContext?

    fun executeFuzzRun(fuzzItem: FuzzItem, iteration: Int, relevantCount: AtomicInteger) {
        try {
            val ctx = doExecuteFuzzRun(fuzzItem, iteration, relevantCount) ?: return
            if (ctx.errors.isNotEmpty()) {
                printFuzzInfo(iteration, ctx)
            }
        } catch (e: Exception) {
        }
    }

    protected fun printFuzzInfo(
        runIndex: Int,
        ctx: FuzzRunContext,
    ) {
        synchronized(this) {
            print("\r")
            ctx.errors.forEach { println(it) }
            println("""
                |    Attempt: $runIndex
                |    Original query: ${ctx.originalQuery}
                |    Result length: ${ctx.originalTuples.size}
                |    Rewritten: ${ctx.rewrittenQuery}
                |    Detections: ${ctx.detections.joinToString { it.toString() }}
                |    Rewritten result length: ${ctx.rewrittenTuples.size}
                |
            """.trimMargin())
        }
    }

    protected fun keysDiffer(originalQueryResult: Result, rewrittenQueryResult: Result): Boolean {
        return originalQueryResult.keys() != rewrittenQueryResult.keys()
    }

    protected fun rewrite(query: String, overrideUsername: String): RewriteResult {
        val ast = parser.parse(query) as AstInternalNode
        val detections = detector.process(ast)
        enforcer.enforce(detections, overrideUsername)
        return RewriteResult(
            query,
            unparser.render(ast),
            detections
        )
    }

    // ========================================================================
    // Check 1: Rewritten result is a subset of the original
    // ========================================================================

    /**
     * Verifies two structural invariants:
     * - Result columns (keys) are unchanged by rewriting.
     * - Rewriting only removes nodes, never adds new ones.
     */
    protected fun checkRewrittenResultIsSubsetOfOriginal(ctx: FuzzRunContext) {
        val isReturnStar = ctx.originalQuery.contains("RETURN DISTINCT *") || ctx.originalQuery.contains("RETURN *")

        if (!isReturnStar && keysDiffer(ctx.originalResult, ctx.rewrittenResult)) {
            ctx.registerError("### ERROR: Different result set!")
        }

        if ((ctx.rewrittenNodes - ctx.originalNodes).isNotEmpty()) {
            ctx.registerError("### ERROR: rewritten query contains more nodes than original")
        }
    }

    // ========================================================================
    // Reporting Infrastructure
    // ========================================================================

    /**
     * Override with a non-null suffix to enable file reporting.
     * Report files will be written to `reports/<timestamp>_<suffix>/`.
     * Leave null (default) to disable file reporting (e.g. in unit tests).
     */
    protected open val reportDirSuffix: String? get() = null

    private val reportDir by lazy {
        reportDirSuffix?.let { suffix ->
            Paths.get("reports",
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmm")) + "_$suffix"
            ).also { if (!it.exists()) it.createDirectories() }
        }
    }

    private val errorWriter: Writer? by lazy {
        reportDir?.let { dir ->
            BufferedWriter(FileWriter((dir / Paths.get("errors.txt")).also {
                if (!it.exists()) it.createFile()
            }.toFile(), true))
        }
    }

    private val statsWriter: Writer? by lazy {
        reportDir?.let { dir ->
            BufferedWriter(FileWriter((dir / Paths.get("stats.txt")).also {
                if (!it.exists()) it.createFile()
            }.toFile(), true))
        }
    }

    protected fun reportError(iteration: Int, ctx: FuzzRunContext) {
        val writer = errorWriter ?: return
        synchronized(writer) {
            ctx.errors.forEach { error -> writer.appendLine(error) }
            writer.appendLine("    Attempt: $iteration")
            writer.appendLine("    Original query: ${ctx.originalQuery}")
            writer.appendLine("    Result length: ${ctx.originalTuples.size}")
            writer.appendLine("    Rewritten: ${ctx.rewrittenQuery}")
            writer.appendLine("    Detections: ${ctx.detections.joinToString { it.toString() }}")
            writer.appendLine("    Rewritten result length: ${ctx.rewrittenTuples.size}")
            writer.appendLine()
            (writer as BufferedWriter).flush()
        }
    }

    protected open fun buildStatsText(header: String): String = header

    protected open val statsFlushInterval: Int = 200
    private var lastStatsFlush = AtomicInteger(0)

    protected fun flushReport(totalQueries: Int, final: Boolean = false) {
        val writer = statsWriter ?: return
        if (!final && totalQueries - lastStatsFlush.get() < statsFlushInterval) return
        lastStatsFlush.set(totalQueries)

        val header = if (final) "=== Final Stats at $totalQueries queries ===" else "--- Stats at $totalQueries queries ---"
        val statsText = buildStatsText(header) + "\n"

        synchronized(writer) {
            writer.append(statsText)
            (writer as BufferedWriter).flush()
        }
    }

    protected fun printStatsToConsole(totalQueries: Int, interval: Int = 50) {
        if (totalQueries % interval == 0) {
            println("\n" + buildStatsText("--- Debug Stats at $totalQueries queries ---") + "---")
        }
    }

    // ========================================================================
    // Base Debug Counters
    // ========================================================================

    protected open class BaseDebugCounters {
        val total = AtomicInteger(0)
        val relevant = AtomicInteger(0)
        val emptyResult = AtomicInteger(0)
        val multipleDetections = AtomicInteger(0)
        val noDetections = AtomicInteger(0)

        fun update(ctx: FuzzRunContext, relevantCount: AtomicInteger) {
            total.incrementAndGet()
            if (ctx.detections.size > 1) multipleDetections.incrementAndGet()
            if (ctx.originalNodes.isEmpty()) {
                emptyResult.incrementAndGet()
            } else if (ctx.detections.isEmpty()) {
                noDetections.incrementAndGet()
            } else {
                relevant.incrementAndGet()
                relevantCount.incrementAndGet()
            }
        }

        open fun statsText(header: String): String = buildString {
            appendLine(header)
            appendLine("  Total:              ${total.get()}")
            appendLine("  Relevant:           ${relevant.get()}")
            appendLine("  Empty result:       ${emptyResult.get()}")
            appendLine("  Multiple detections: ${multipleDetections.get()}")
            appendLine("  No detections:      ${noDetections.get()}")
        }
    }

}
