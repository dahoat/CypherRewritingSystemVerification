package at.daho.cypherrewriting.fuzzingexperiments

import fuzzer.cypher.fuzzer.random.RandomCypherFuzzer
import fuzzer.cypher.fuzzer.random.RandomCypherFuzzerSettings
import org.neo4j.driver.Session
import org.neo4j.driver.exceptions.ClientException
import org.neo4j.driver.exceptions.Neo4jException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import kotlin.random.Random

@Component
@Profile("with-database")
class FuzzRunnerWithDatabase: ApplicationRunner, FuzzRunnerBase() {

    @Autowired
    lateinit var session: Session


    override fun run(args: ApplicationArguments) {

        for (query in randomFuzzerGenerator()) {
            val ast = cypherParser.parse(query)
            val unparedQuery = astRenderer.render(ast)

            if (query != unparedQuery) {
                reportQueryNotEqual(query, unparedQuery)
            }

            try {
                session.run(unparedQuery)
            } catch (e: ClientException) {
                val cause = e.gqlCause().orElseThrow { e }
                when (cause) {
                    is Neo4jException -> {
                        if(cause.gqlStatus() in acceptableErrorCodes) {
                            reportAcceptableError(query, cause.gqlStatus())
                        } else {
                            reportQueryNotExecutable(query, unparedQuery,cause)
                        }
                    }
                    else -> reportQueryNotExecutable(query, unparedQuery, e)
                }
            } catch (e: Exception) {
                reportQueryNotExecutable(unparedQuery, unparedQuery, e)
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

