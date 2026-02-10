package at.daho.cypherrewriting.cypherverificatorairbnb

import at.daho.cypherrewriting.verification.CypherSchema
import at.daho.cypherrewriting.verification.FuzzGenerator
import at.daho.cypherrewriting.verification.FuzzSettings
import at.daho.cypherrewriting.verification.fuzzSettings
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstInternalNode
import at.jku.faw.symspace.cypherrewriter.core.cypher.detector.Detection
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
import org.neo4j.driver.Record
import org.neo4j.driver.Result
import org.neo4j.driver.TransactionConfig
import org.neo4j.driver.internal.types.InternalTypeSystem
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger

private const val INVALID_USERID = "0"

@Component
@Profile("airbnb-fuzzer")
class AirbnbFuzzer : ApplicationRunner {

    @Autowired
    private lateinit var sessionBean: SessionBean

    @Autowired
    private lateinit var parser: CypherRewritingParser

    @Autowired
    private lateinit var detector: PermissionDetector

    @Autowired
    private lateinit var enforcer: CypherEnforcer

    @Autowired
    private lateinit var unparser: CypherRewritingUnparser

    private val transactionConfig = TransactionConfig.builder().withTimeout(Duration.ofSeconds(1)).build()

    override fun run(args: ApplicationArguments) {

        val hostIds = getHostIds()

        //runFuzzer()
        runCoroutineFuzzer()

    }

    private fun getHostIds(): List<Long> {
        return sessionBean.session().run("MATCH (h:Host) RETURN h.id as hostId").list { it.get("hostId").asLong() }
    }

    fun runFuzzer() {

        val schema = constructSchema()
        val fuzzSettings = constructFuzzingSettings()

        val i = AtomicInteger(0)
        val relevantCount = AtomicInteger(0)
        println("Start fuzzing")
        repeat(100) {
            println("Fetching new set...")
            FuzzGenerator(schema, fuzzSettings).take(5000).parallelStream().forEach { query ->
                val currentIdx = i.getAndIncrement()
                if (currentIdx % 10 == 0) {
                    print("\rAttempt $currentIdx")
                }
                executeFuzzRun(query, currentIdx, relevantCount)
            }
            println()
        }

    }

    fun runCoroutineFuzzer() {
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        val i = AtomicInteger(0)
        val relevantCount = AtomicInteger(0)

        val schema = constructSchema()
        val fuzzSettings = constructFuzzingSettings()
        val fuzzGenerator = FuzzGenerator(schema, fuzzSettings)

        runBlocking {
            (1..18).map { threadId ->
                scope.launch {
                    fuzzGenerator.forEach {
                        val iteration = i.getAndIncrement()
                        if (iteration % 10 == 0) {
                            print("\rAttempt $iteration (${relevantCount.get()} relevant queries)")
                        }
                        executeFuzzRun(it, iteration, relevantCount)
                    }
                }
            }.joinAll()
        }
    }

    private fun constructFuzzingSettings(): FuzzSettings = fuzzSettings {
        pattern {
            length = 1..3
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
                elementsRange = 1..3
            }

            returnSettings {
                propertyAccessProbability = 0.0
            }
        }
    }

    private fun constructSchema(): CypherSchema = CypherSchema {
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
        cypherRelationship(userNode, "WROTE", userNode)

        fetchValuesFromDatabase(sessionBean.session())
    }

    private fun isNodeWithLabel(key: String, entry: org.neo4j.driver.Record, label: String): Boolean {
        if (entry[key].type() == InternalTypeSystem.TYPE_SYSTEM.NODE()) {
            val node = entry[key].asNode()
            return node.labels().contains(label)
        }
        return false
    }

    private fun rewrite(query: String, overrideUsername: String): RewriteResult {
        val ast = parser.parse(query) as AstInternalNode
        val detections = detector.process(ast)
        enforcer.enforce(detections, overrideUsername)
        return RewriteResult(
            query,
            unparser.render(ast),
            detections
        )
    }

    private data class RewriteResult(
        val originalQuery: String,
        val rewrittenQuery: String,
        val detections: List<Detection>
    )

    private fun executeFuzzRun(query: String, i: Int, relevantCount: AtomicInteger) {
        try {

            val session = sessionBean.session()
            val rewrittenCtx = rewrite(query, INVALID_USERID)

            var containsError = false

            val originalQueryResult = session.run(query, transactionConfig)
            val originalTuples = originalQueryResult.list()

            val rewrittenQueryResult = session.run(rewrittenCtx.rewrittenQuery, transactionConfig)
            val rewrittenTuples = rewrittenQueryResult.list()

            val originalUserNodes = getUserNodes(originalTuples).toSet()
            val rewrittenUserNodes = getUserNodes(rewrittenTuples).toSet()

            if (originalUserNodes.isNotEmpty()) {
                relevantCount.incrementAndGet()
            }

            if(keysDiffer(originalQueryResult, rewrittenQueryResult) && !(rewrittenCtx.originalQuery.contains("RETURN DISTINCT *") || rewrittenCtx.originalQuery.contains("RETURN *"))) {
                synchronized(this) {
                    println("\r### ERROR: Different result set!")
                    containsError = true
                }
            }

            if ((rewrittenUserNodes - originalUserNodes).isNotEmpty()) {
                synchronized(this) {
                    println("\r### ERROR: rewritten query contains more User nodes than original")
                    containsError = true
                }
            }

            if(rewrittenUserNodes.any { it["id"].asLong() != INVALID_USERID.toLong() }) {
                synchronized(this) {
                    println("\r### ERROR: rewritten query contains unauthorized result")
                    containsError = true
                }
            }

            if (originalUserNodes.isNotEmpty() && rewrittenCtx.detections.isEmpty()) {
                synchronized(this) {
                    println("\r### ERROR: relevant query was not rewritten")
                    containsError = true
                }
            }

            for (matchingUserNode in originalUserNodes) {
                val userId = matchingUserNode["id"].toString()
                val validUserRewrittenCtx = rewrite(query, userId)


                val validUserTuples = session.run(validUserRewrittenCtx.rewrittenQuery, transactionConfig).list()
                val containsUnauthorizedNode = getUserNodes(validUserTuples).any { it["id"].asLong() != userId.toLong() }
                if (containsUnauthorizedNode) {
                    println("\r### ERROR: The rewritten query with valid contains unauthorized result.")
                    println("    ${validUserRewrittenCtx.rewrittenQuery}")
                }

            }

            if(containsError) {
                synchronized(this) {
                    printFuzzInfo(i, query, originalTuples.size, rewrittenCtx, rewrittenTuples.size)
                }
            }

        } catch (e: Exception) {
        }
    }

    private fun keysDiffer(originalQueryResult: Result, rewrittenQueryResult: Result): Boolean {
        return originalQueryResult.keys() != rewrittenQueryResult.keys()
    }

    private fun printFuzzInfo(
        runIndex: Int,
        query: String,
        originalTupleSize: Int,
        rewrittenCtx: RewriteResult,
        rewrittenTupleSize: Int
    ) {
        println("""
            |    Attempt: $runIndex
            |    Original query: $query
            |    Result length: ${originalTupleSize}
            |    Rewritten: ${rewrittenCtx.rewrittenQuery}
            |    Detections: ${rewrittenCtx.detections.joinToString { it.toString() }}
            |    Rewritten result length: ${rewrittenTupleSize}
            |
        """.trimMargin())
    }

    fun getUserNodes(results: List<Record>): List<org.neo4j.driver.types.Node> {
        return results.flatMap { entry ->
            entry.keys()
                .filter { key -> isNodeWithLabel(key, entry, "User") }
                .map { key -> entry[key].asNode() }
        }
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
