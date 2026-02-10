package at.daho.cypherrewriting.verification.at.daho.cypherrewriting.verification

import at.daho.cypherrewriting.verification.CypherSchema
import at.daho.cypherrewriting.verification.FuzzGenerator
import at.daho.cypherrewriting.verification.FuzzSettings
import at.daho.cypherrewriting.verification.fuzzSettings
import org.neo4j.driver.AuthTokens
import org.neo4j.driver.GraphDatabase
import org.neo4j.driver.Session
import org.neo4j.driver.TransactionConfig
import java.time.Duration

fun main() {

    val uri = "bolt://localhost:7687" // add uri
    val user = "neo4j" // add user
    val password = "adminadmin" // add password
    val session = GraphDatabase.driver(uri, AuthTokens.basic(user, password)).session()

    val schema = CypherSchema {
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

        fetchValuesFromDatabase(session)
    }

    val fuzzSettings = fuzzSettings {
        pattern {
            length = 1..3
            node {
                defectLabelProbability = 0.0
                defectPropertyProbability = 0.0
                defectPropertyTypeProbability = 0.0
                propertiesPerNode = 0..3
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
        }
    }


    printQueries(schema, fuzzSettings)
    checkAgainstDB(schema, fuzzSettings, session)
}

private fun printQueries(schema: CypherSchema, fuzzSettings: FuzzSettings) {
    FuzzGenerator(schema, fuzzSettings).take(100).forEach { println(it) }
}

private fun checkAgainstDB(schema: CypherSchema, fuzzSettings: FuzzSettings, session: Session) {
    val transactionConfig = TransactionConfig.builder().withTimeout(Duration.ofSeconds(2)).build()
    FuzzGenerator(schema, fuzzSettings).take(1000).forEach {

        try {
            val res = session.run(it, transactionConfig)
            val size = res.list().size
            if(size > 0) {
                println(it)
                println(size)
            }
        } catch (e: Exception) {
            //println("Error")
        }
    }
}
