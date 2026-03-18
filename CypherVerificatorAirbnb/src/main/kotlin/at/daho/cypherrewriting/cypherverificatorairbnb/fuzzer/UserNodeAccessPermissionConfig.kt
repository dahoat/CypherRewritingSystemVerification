package at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer

import at.jku.faw.symspace.cypherrewriter.core.cypher.ArgumentType
import at.jku.faw.symspace.cypherrewriter.core.cypher.AuthorizationLevel
import at.jku.faw.symspace.cypherrewriter.core.cypher.ConditionExpression
import at.jku.faw.symspace.cypherrewriter.core.cypher.FilterTemplate
import at.jku.faw.symspace.cypherrewriter.core.cypher.FilterType
import at.jku.faw.symspace.cypherrewriter.core.cypher.LabelMatchStrategy
import at.jku.faw.symspace.cypherrewriter.core.cypher.PatternMatchStrategy
import at.jku.faw.symspace.cypherrewriter.core.cypher.PermissionConfig
import at.jku.faw.symspace.cypherrewriter.core.cypher.Policy
import at.jku.faw.symspace.cypherrewriter.core.cypher.ReturnType
import at.jku.faw.symspace.cypherrewriter.core.cypher.Rule
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

@Component
@Profile("user-node-access-fuzzer")
object UserNodeAccessPermissionConfig: PermissionConfig(listOf(
    Policy(
        "(u:User)",
        mapOf(
            "u" to PatternMatchStrategy(LabelMatchStrategy.CONTAINS_ANY, true)
        ),
        listOf(
            Rule("userEditOnlyByOwner", "u",
                listOf(
                    ConditionExpression("u", FilterType.ANY, ReturnType.RETURNED_AS_VALUE, comment = "Direct access: MATCH (u) RETURN u"),
                ),
                "currentUserIsNodeOwner",
                AuthorizationLevel.OWNER_LEVEL,
                "Only Users are allowed to fetch their nodes for writing."
            )
        )
    ),
), listOf(
    FilterTemplate("currentUserIsNodeOwner", AuthorizationLevel.OWNER_LEVEL,
        "%s.id = %s",
        listOf(ArgumentType.RESOURCE_VARIABLE, ArgumentType.USERNAME))
))
