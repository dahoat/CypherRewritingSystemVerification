package at.daho.cypherrewriting.fuzzingexperiments

import fuzzer.cypher.fuzzer.random.RandomCypherFuzzer
import fuzzer.cypher.fuzzer.random.RandomCypherFuzzerSettings
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.stereotype.Component
import kotlin.random.Random
import at.jku.faw.symspace.cypherrewriter.core.cypher.parser.CypherRewritingParser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser

@Component
class FuzzRunner: ApplicationRunner {

    @Autowired
    lateinit var cypherParser: CypherRewritingParser

    @Autowired
    lateinit var astRenderer: CypherRewritingUnparser

    override fun run(args: ApplicationArguments) {
        for (query in executeRandomFuzzer()) {
            val ast = cypherParser.parse(query)
            val unparedQuery = astRenderer.render(ast)

            println(query)
            println(unparedQuery)
            println()
        }



        println("Running Fuzz")
    }

    fun executeRandomFuzzer(): Sequence<String> {
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
            .take(10)
    }
}

