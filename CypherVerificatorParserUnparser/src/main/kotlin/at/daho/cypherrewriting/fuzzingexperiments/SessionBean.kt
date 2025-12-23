package at.daho.cypherrewriting.fuzzingexperiments

import org.neo4j.driver.AuthTokens
import org.neo4j.driver.GraphDatabase
import org.neo4j.driver.Session
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

@Component
@Profile("with-database")
class SessionBean {

    @Value("\${app.db.uri}")
    private lateinit var dbUri: String

    @Value("\${app.db.username}")
    private lateinit var username: String

    @Value("\${app.db.password}")
    private lateinit var password: String

    @Bean
    fun session(): Session {
        val driver = GraphDatabase.driver(dbUri, AuthTokens.basic(username, password))
        return driver.session()
    }
}
