package at.daho.cypherrewriting.cypherverificatorairbnb

import org.neo4j.driver.AuthTokens
import org.neo4j.driver.Config
import org.neo4j.driver.Driver
import org.neo4j.driver.GraphDatabase
import org.neo4j.driver.Session
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.stereotype.Component
import java.util.concurrent.TimeUnit

@Component
class SessionBean(
    @Value("\${app.db.uri}") private val dbUri: String,
    @Value("\${app.db.username}") private var username: String,
    @Value("\${app.db.password}") private var password: String
) {

    val driver: Driver = GraphDatabase.driver(
        dbUri,
        AuthTokens.basic(username, password),
        Config.builder()
            .withMaxConnectionPoolSize(50)
            .withConnectionAcquisitionTimeout(30, TimeUnit.SECONDS)
            .withMaxConnectionLifetime(1, TimeUnit.HOURS)
            .withConnectionLivenessCheckTimeout(5, TimeUnit.MINUTES)
            .build()
    )

    @Bean
    fun session(): Session {
        return driver.session()
    }
}
