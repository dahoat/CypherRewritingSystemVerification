package at.daho.cypherrewriting.cypherverificatorairbnb

import at.jku.faw.symspace.cypherrewriter.core.CypherRewritingCoreLibConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Import

@SpringBootApplication
@Import(value = [CypherRewritingCoreLibConfig::class])
class CypherVerificatorAirbnbApplication

fun main(args: Array<String>) {
    runApplication<CypherVerificatorAirbnbApplication>(*args)
}
