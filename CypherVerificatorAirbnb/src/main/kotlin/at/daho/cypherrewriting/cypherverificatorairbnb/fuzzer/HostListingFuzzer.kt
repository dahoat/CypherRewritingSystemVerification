package at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer

import at.daho.cypherrewriting.cypherverificatorairbnb.SessionBean
import at.daho.cypherrewriting.cypherverificatorairbnb.model.FuzzRunContext
import at.daho.cypherrewriting.verification.FuzzItem
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.PermissionDetector
import at.jku.faw.symspace.cypherrewriter.core.cypher.enforcer.CypherEnforcer
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import org.neo4j.driver.Record
import org.neo4j.driver.Session
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.util.concurrent.atomic.AtomicInteger


private const val INVALID_HOSTID = "0"
private const val QUERY_HOST_ID_FOR_LISTING =
    "MATCH (h:Host)-[:HOSTS]->(l:Listing {id: \$listingId}) RETURN h.id as hostId"

@Component
@Profile("host-listing-fuzzer")
class HostListingFuzzer(
    sessionBean: SessionBean,
    parser: CypherRewritingParser,
    detector: PermissionDetector,
    enforcer: CypherEnforcer,
    unparser: CypherRewritingUnparser
) : FuzzBaseRunner(sessionBean, parser, detector, enforcer, unparser), ApplicationRunner {

    override val reportDirSuffix: String? get() = "host-listing"

    override fun run(args: ApplicationArguments) {
        Runtime.getRuntime().addShutdownHook(Thread { flushReport(debugCounters.total.get(), final = true) })
        runCoroutineFuzzer()
        flushReport(debugCounters.total.get(), final = true)
    }

    // ========================================================================
    // Main Verification Flow
    // ========================================================================

    override fun doExecuteFuzzRun(fuzzItem: FuzzItem, iteration: Int, relevantCount: AtomicInteger): FuzzRunContext {
        val ctx = prepareQueries(fuzzItem, RELEVANT_LABELS, INVALID_HOSTID)

        updateDebugCounters(ctx, relevantCount)

        // Check 1: Rewritten result is a subset of the original
        checkRewrittenResultIsSubsetOfOriginal(ctx)

        // Check 2: Rewritten query for invalid host must be empty
        checkNoResultsForInvalidHost(ctx)

        // Check 3: For each original listing, check no unauthorized listings leak
        checkPerHostCorrectness(ctx)

        if (ctx.errors.isNotEmpty()) {
            reportError(iteration, ctx)
        }

        flushReport(debugCounters.total.get())

        return ctx
    }

    // ========================================================================
    // Check 2: No results for invalid host
    // ========================================================================

    private fun checkNoResultsForInvalidHost(ctx: FuzzRunContext) {
        if (ctx.originalNodes.isNotEmpty() && ctx.detections.isEmpty()) {
            ctx.registerError("### ERROR: relevant query was not rewritten")
        } else if (ctx.rewrittenNodes.isNotEmpty()) {
            ctx.registerError("### ERROR: rewritten query contains Listing nodes for invalid host")
        }
    }

    // ========================================================================
    // Check 3: Per-host correctness (soundness)
    // ========================================================================

    private fun checkPerHostCorrectness(ctx: FuzzRunContext) {
        for (listingNode in ctx.originalNodes) {
            val listingId = listingNode["id"].toString()
            val hostId = getHostIdForListing(ctx.session, listingId)

            if (hostId != null) {
                val leakDetected = leaksOtherHostsListings(ctx, hostId)
                if (leakDetected) {
                    break
                }
            } else {
                ctx.registerError("### ERROR: could not extract hostid for $listingId")
            }
        }
    }

    private fun leaksOtherHostsListings(ctx: FuzzRunContext, hostId: String): Boolean {
        val validHostRewrittenCtx = rewrite(ctx.originalQuery, hostId)
        val validHostTuples = ctx.session.run(validHostRewrittenCtx.rewrittenQuery, transactionConfig).list()

        val unauthorizedListingsPresent = containsUnauthorizedListings(ctx.session, validHostTuples, hostId)
        if (unauthorizedListingsPresent) {
            ctx.registerError(
                "### ERROR: The rewritten query with valid host contains unauthorized Listing.\n" +
                        "    ${validHostRewrittenCtx.rewrittenQuery}"
            )
            return true
        }
        return false
    }

    private fun containsUnauthorizedListings(session: Session, validHostTuples: List<Record>, hostId: String): Boolean {
        return getRelevantNodes(validHostTuples, RELEVANT_LABELS).any { listing ->
            val listingId = listing["id"].toString()
            val ownerHostId = getHostIdForListing(session, listingId)
            ownerHostId != hostId
        }
    }

    private fun getHostIdForListing(session: Session, listingId: String): String? {
        return session.run(
            QUERY_HOST_ID_FOR_LISTING,
            mapOf("listingId" to listingId),
            transactionConfig
        ).list().firstOrNull()?.get("hostId")?.toString()
    }

    // ========================================================================
    // Debug Counters
    // ========================================================================

    private val debugCounters = BaseDebugCounters()

    private fun updateDebugCounters(ctx: FuzzRunContext, relevantCount: AtomicInteger) {
        debugCounters.update(ctx, relevantCount)
        printStatsToConsole(debugCounters.total.get())
    }

    override fun buildStatsText(header: String): String = debugCounters.statsText(header)

    companion object {
        private val RELEVANT_LABELS = listOf("Listing")
    }
}
