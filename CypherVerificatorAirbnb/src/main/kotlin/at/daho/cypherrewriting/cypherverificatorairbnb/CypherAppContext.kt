package at.daho.cypherrewriting.cypherverificatorairbnb

import at.jku.faw.symspace.cypherrewriter.core.cypher.CypherAppContext
import org.springframework.stereotype.Component

@Component
object AirbnbCypherAppContext: CypherAppContext {
    override var currentUsername: String = ""
}
