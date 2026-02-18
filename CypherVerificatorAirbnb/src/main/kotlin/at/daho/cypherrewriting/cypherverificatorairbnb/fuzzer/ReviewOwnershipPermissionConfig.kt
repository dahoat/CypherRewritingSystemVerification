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
@Profile("review-ownership-fuzzer")
object ReviewOwnershipPermissionConfig : PermissionConfig(listOf(
    Policy(
        "(r:Review)",
        mapOf(
            "r" to PatternMatchStrategy(LabelMatchStrategy.CONTAINS_ANY, true)
        ),
        listOf(
            Rule("reviewOwnership", "r",
                listOf(
                    ConditionExpression("r", FilterType.ANY, ReturnType.ANY_RETURN,
                        comment = "Any return including aggregation: MATCH (r:Review) RETURN r or RETURN count(r)"),
                ),
                "userWroteReview",
                AuthorizationLevel.OWNER_LEVEL,
                "Users are only allowed to access their own Reviews. Protected against blind (simulated) writing via aggregation.")
        )
    ),
), listOf(
    FilterTemplate("userWroteReview", AuthorizationLevel.OWNER_LEVEL,
        "(:User {id: %s})-[:WROTE]->(%s)",
        listOf(ArgumentType.USERNAME, ArgumentType.RESOURCE_VARIABLE))
))
