package at.daho.cypherrewriting.cypherverificatorairbnb.fuzzer

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
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

@Component
@Profile("identify-review-author-fuzzer")
object IdentifyReviewAuthorPermissionConfig : PermissionConfig(listOf(
    Policy(
        "(r:Review)--(u:User)",
        mapOf(
            "r" to PatternMatchStrategy(LabelMatchStrategy.CONTAINS_ANY, true)
        ),
        listOf(
            Rule("reviewAuthorsReadByHost", "r",
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
                        ),
                        ConditionCombination(ConditionBoolean.AND,
                            ConditionExpression("r", FilterType.ANY, ReturnType.ANY_RETURN),
                            ConditionExpression("u", FilterType.FILTERED, ReturnType.NO_RETURN),
                            comment = "Indirect access: MATCH (r)--(u) WHERE u = ... RETURN r)"
                        )
                    )
                ),
                "authorizeHostOnReview",
                AuthorizationLevel.AUTHORIZED_LEVEL,
                "Only Hosts are allowed to see the authors of reviews on their Listings.")
        )
    ),
), listOf(
    FilterTemplate("authorizeHostOnReview", AuthorizationLevel.AUTHORIZED_LEVEL,
        "(%s:Review)-[:REVIEWS]->(:Listing)<-[:HOSTS]-(:Host {id: %s})",
        listOf(ArgumentType.RESOURCE_VARIABLE, ArgumentType.USERNAME))
))
