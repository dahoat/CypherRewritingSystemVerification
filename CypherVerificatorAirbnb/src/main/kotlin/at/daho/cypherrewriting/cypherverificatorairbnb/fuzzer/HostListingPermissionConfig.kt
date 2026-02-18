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
@Profile("host-listing-fuzzer")
object HostListingPermissionConfig : PermissionConfig(listOf(
    Policy(
        "(l:Listing)",
        mapOf(
            "l" to PatternMatchStrategy(LabelMatchStrategy.CONTAINS_ANY, true)
        ),
        listOf(
            Rule("hostListingAccess", "l",
                listOf(
                    ConditionExpression("l", FilterType.ANY, ReturnType.RETURNED_AS_VALUE,
                        comment = "Direct access: MATCH (l:Listing) RETURN l — intentionally no aggregation protection"),
                ),
                "hostOwnsListing",
                AuthorizationLevel.OWNER_LEVEL,
                "Hosts are only allowed to see their own Listings. Aggregations are intentionally NOT protected.")
        )
    ),
), listOf(
    FilterTemplate("hostOwnsListing", AuthorizationLevel.OWNER_LEVEL,
        "(:Host {id: %s})-[:HOSTS]->(%s)",
        listOf(ArgumentType.USERNAME, ArgumentType.RESOURCE_VARIABLE))
))
