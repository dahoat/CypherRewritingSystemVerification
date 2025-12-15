package at.daho.cypherrewriting.fuzzingexperiments

import at.jku.faw.symspace.cypherrewriter.core.cypher.PermissionConfig
import org.springframework.stereotype.Component

@Component
object MyPermissionConfig: PermissionConfig(emptyList(), emptyList())
