package at.daho.cypherrewriting.fuzzingexperiments

import fuzzer.cypher.fuzzer.random.RandomCypherFuzzer
import fuzzer.cypher.fuzzer.random.RandomCypherFuzzerSettings
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.stereotype.Component
import kotlin.random.Random
import org.springframework.context.annotation.Profile

@Component
@Profile("!with-database")
class FuzzRunner: ApplicationRunner, FuzzRunnerBase() {


    override fun run(args: ApplicationArguments) {
        for (query in randomFuzzerGenerator()) {
            val ast = cypherParser.parse(query)
            val unparsedQuery = astRenderer.render(ast)

            if (query != unparsedQuery) {
                println(query)
                println(unparsedQuery)
                println()
            }

            queryCount++
            reportStats()
        }

    }

    fun randomFuzzerGenerator(): Sequence<String> {
        val randomCypherSettings = RandomCypherFuzzerSettings(
            random = Random(123),
            nodes = 5,
            nodesInMatch = 2,
            nodeAttributes = 7,
            nodeConditions = 3,
            returningNodes = 2,
            relationships = 4,
            relationshipsInMatch = 2,
            relationshipAttributes = 4,
            relationshipConditions = 3,
            returningRelationships = 2,

            )
        return RandomCypherFuzzer(randomCypherSettings)
            .fuzz()
    }
}

