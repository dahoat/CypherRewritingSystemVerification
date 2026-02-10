package at.daho.cypherrewriting.cypherverificatorairbnb

import at.jku.faw.symspace.cypherrewriter.core.cypher.ArgumentType
import at.jku.faw.symspace.cypherrewriter.core.cypher.AuthorizationLevel
import at.jku.faw.symspace.cypherrewriter.core.cypher.ConditionBoolean
import at.jku.faw.symspace.cypherrewriter.core.cypher.ConditionCombination
import at.jku.faw.symspace.cypherrewriter.core.cypher.ConditionExpression
import at.jku.faw.symspace.cypherrewriter.core.cypher.FilterTemplate
import at.jku.faw.symspace.cypherrewriter.core.cypher.FilterType
import at.jku.faw.symspace.cypherrewriter.core.cypher.LabelMatchStrategy
import at.jku.faw.symspace.cypherrewriter.core.cypher.PatternMatchStrategy
import at.jku.faw.symspace.cypherrewriter.core.cypher.PermissionConfig
import at.jku.faw.symspace.cypherrewriter.core.cypher.Policy
import at.jku.faw.symspace.cypherrewriter.core.cypher.ReturnType
import at.jku.faw.symspace.cypherrewriter.core.cypher.Rule
import org.springframework.stereotype.Component

@Component
object AirbnbPermissionConfig: PermissionConfig(listOf(
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
                "Only Users are allowed to fetch their nodes for writing.")
        )
    ),
), listOf(
    FilterTemplate("currentUserIsNodeOwner", AuthorizationLevel.OWNER_LEVEL,
        "%s.id = %s",
        listOf(ArgumentType.RESOURCE_VARIABLE, ArgumentType.USERNAME))
))

/*
object AirbnbPermissionConfig: PermissionConfig(listOf(
    Policy(
        "(r:Review)--(u:User)",
        mapOf(
            "r" to PatternMatchStrategy(LabelMatchStrategy.CONTAINS_ANY, true)
        ),
        listOf(
            Rule("reviewAuthorsReadByHost", "u",
                listOf(
                    ConditionCombination(ConditionBoolean.OR,
                        ConditionCombination(
                            ConditionBoolean.AND,
                            ConditionExpression("u", FilterType.ANY, ReturnType.ANY_RETURN),
                            ConditionExpression("r", FilterType.ANY, ReturnType.ANY_RETURN),
                            comment = "Direct access: MATCH (r)--(u) RETURN r, u"
                        ),
                        ConditionCombination(ConditionBoolean.AND,
                            ConditionExpression("r", FilterType.FILTERED, ReturnType.NO_RETURN),
                            ConditionExpression("u", FilterType.ANY, ReturnType.ANY_RETURN),
                            comment = "Indirect access: MATCH (r)--(u) WHERE r = ... RETURN u)"
                        )
                    )
                ),
                "authorizeHostOnReview",
                AuthorizationLevel.AUTHORIZED_LEVEL,
                "Only Hosts are allowed to see the autors of reviews.")
        )
    ),
), listOf(
    FilterTemplate("authorizeHostOnReview", AuthorizationLevel.AUTHORIZED_LEVEL,
        "(%s:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(:Host {id: %s})",
        listOf(ArgumentType.RESOURCE_VARIABLE, ArgumentType.USERNAME))
))
*/
