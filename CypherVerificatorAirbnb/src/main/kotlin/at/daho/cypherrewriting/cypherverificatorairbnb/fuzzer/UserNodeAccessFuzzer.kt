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
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.util.concurrent.atomic.AtomicInteger

private const val INVALID_USERID = "0"

@Component
@Profile("user-node-access-fuzzer")
class AirbnbFuzzer(
    sessionBean: SessionBean,
    parser: CypherRewritingParser,
    detector: PermissionDetector,
    enforcer: CypherEnforcer,
    unparser: CypherRewritingUnparser
) : FuzzBaseRunner(sessionBean, parser, detector, enforcer, unparser), ApplicationRunner {

    override val reportDirSuffix: String? get() = "airbnb"

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
        }
    }

    // ========================================================================
    // Main Verification Flow
    // ========================================================================

    override fun doExecuteFuzzRun(fuzzItem: FuzzItem, iteration: Int, relevantCount: AtomicInteger): FuzzRunContext {
        val ctx = prepareQueries(fuzzItem, RELEVANT_LABELS_USER, INVALID_USERID)

        updateDebugCounters(ctx, relevantCount)

        // Check 1: Rewritten result is a subset of the original
        checkRewrittenResultIsSubsetOfOriginal(ctx)

        // Check 2: Rewritten query for invalid user must contain no unauthorized results
        checkNoUnauthorizedResults(ctx)

        // Check 3: Relevant queries must have detections
        checkRelevantQueryRewritten(ctx)

        // Check 4: For each original user, check no unauthorized users leak
        checkPerUserCorrectness(ctx)

        if (ctx.errors.isNotEmpty()) {
            reportError(iteration, ctx)
        }

        flushReport(debugCounters.total.get())

        return ctx
    }

    // ========================================================================
    // Check 2: No unauthorized results for invalid user
    // ========================================================================

    private fun checkNoUnauthorizedResults(ctx: FuzzRunContext) {
        if (ctx.rewrittenNodes.any { it["id"].toString() != INVALID_USERID }) {
            ctx.registerError("### ERROR: rewritten query contains unauthorized result")
        }
    }

    // ========================================================================
    // Check 3: Relevant queries must be rewritten
    // ========================================================================

    private fun checkRelevantQueryRewritten(ctx: FuzzRunContext) {
        if (ctx.originalNodes.isNotEmpty() && ctx.detections.isEmpty()) {
            ctx.registerError("### ERROR: relevant query was not rewritten")
        }
    }

    // ========================================================================
    // Check 4: Per-user correctness (soundness)
    // ========================================================================

    private fun checkPerUserCorrectness(ctx: FuzzRunContext) {
        for (userNode in ctx.originalNodes) {
            val userId = userNode["id"].toString()
            val validUserRewrittenCtx = rewrite(ctx.originalQuery, userId)

            val validUserTuples = ctx.session.run(validUserRewrittenCtx.rewrittenQuery, transactionConfig).list()
            val containsUnauthorizedNode = getRelevantNodes(validUserTuples, RELEVANT_LABELS_USER)
                .any { it["id"].toString() != userId }

            if (containsUnauthorizedNode) {
                ctx.registerError(
                    "### ERROR: The rewritten query with valid user contains unauthorized result.\n" +
                            "    ${validUserRewrittenCtx.rewrittenQuery}"
                )
            }
        }
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
        private val RELEVANT_LABELS_USER = listOf("User")
    }
}

/*

### ERROR: rewritten query contains unauthorized result
   Attempt: 7638
   Original query: MATCH (var0:User) WHERE var0.name STARTS WITH "A" XOR var0.name = "Paula Jane" RETURN * ORDER BY var0 ASC, var0, var0 LIMIT 48
   Result length: 48
   Rewritten: MATCH (var0:User) WHERE var0.id = 123456 AND var0.name STARTS WITH "A" XOR var0.name = "Paula Jane" RETURN * ORDER BY var0 ASC, var0, var0 LIMIT 48
   Detections: Detection(Rule: userEditOnlyByOwner, AuthorizationLevel: OWNER_LEVEL)
   Rewritten result length: 0

### ERROR: rewritten query contains unauthorized result
   Attempt: 39042
   Original query: MATCH (var0:Host), (var1), (var2:User) WHERE var2.id = 104110720 XOR var2.name STARTS WITH "Hei Ma" OR var2.name <> "value316" RETURN var0, var1, var2 LIMIT 98
   Result length: 98
   Rewritten: MATCH (var0:Host), (var1), (var2:User) WHERE var2.id = 123456 AND var1.id = 123456 AND var2.id = 104110720 XOR var2.name STARTS WITH "Hei Ma" OR var2.name <> "value316" RETURN var0, var1, var2 LIMIT 98
   Detections: Detection(Rule: userEditOnlyByOwner, AuthorizationLevel: OWNER_LEVEL), Detection(Rule: userEditOnlyByOwner, AuthorizationLevel: OWNER_LEVEL)
   Rewritten result length: 0

### ERROR: rewritten query contains unauthorized result
   Attempt: 45649
   Original query: MATCH (var0:User) WHERE var0.name ENDS WITH "Marcus" XOR var0.id = 39259031 XOR var0.name STARTS WITH "D" RETURN var0 SKIP 3 LIMIT 4
   Result length: 4
   Rewritten: MATCH (var0:User) WHERE var0.id = 123456 AND var0.name ENDS WITH "Marcus" XOR var0.id = 39259031 XOR var0.name STARTS WITH "D" RETURN var0 SKIP 3 LIMIT 4
   Detections: Detection(Rule: userEditOnlyByOwner, AuthorizationLevel: OWNER_LEVEL)
   Rewritten result length: 0

### ERROR: rewritten query contains unauthorized result
   Attempt: 78163
   Original query: MATCH (var0:User) WHERE var0.name STARTS WITH "Phyll" XOR var0.name STARTS WITH "Kang" RETURN var0 LIMIT 16
   Result length: 16
   Rewritten: MATCH (var0:User) WHERE var0.id = 123456 AND var0.name STARTS WITH "Phyll" XOR var0.name STARTS WITH "Kang" RETURN var0 LIMIT 16
   Detections: Detection(Rule: userEditOnlyByOwner, AuthorizationLevel: OWNER_LEVEL)
   Rewritten result length: 0

### ERROR: rewritten query contains unauthorized result
   Attempt: 80790
   Original query: MATCH (var0:User{id: 24837397})-[var1]->() WHERE var1.alpha674 <> -553 OR var0.id <> 20815159 RETURN var0
   Result length: 1
   Rewritten: MATCH (var0:User{id: 24837397})-[var1]->() WHERE var0.id = 123456 AND var1.alpha674 <> -553 OR var0.id <> 20815159 RETURN var0
   Detections: Detection(Rule: userEditOnlyByOwner, AuthorizationLevel: OWNER_LEVEL)
   Rewritten result length: 0

 */
