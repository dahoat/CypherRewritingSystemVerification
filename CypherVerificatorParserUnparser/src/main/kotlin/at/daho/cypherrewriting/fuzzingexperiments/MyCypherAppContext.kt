package at.daho.cypherrewriting.fuzzingexperiments

import at.jku.faw.symspace.cypherrewriter.core.cypher.CypherAppContext
import org.springframework.stereotype.Component

@Component
object MyCypherAppContext: CypherAppContext {
    override var currentUsername: String
        get() = "Asterix"
        set(value) {}

}
