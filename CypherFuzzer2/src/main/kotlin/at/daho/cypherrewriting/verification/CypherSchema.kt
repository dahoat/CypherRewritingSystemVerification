package at.daho.cypherrewriting.verification

import org.neo4j.driver.Session
import org.neo4j.driver.Value
import kotlin.reflect.KClass


class CypherSchema(init: CypherSchema.() -> Unit) {

    val nodes = mutableSetOf<CypherNode>()
    val relationships = mutableSetOf<CypherRelationship>()

    init {
        init()
    }

    fun cypherNode(vararg labels: String, init: CypherNode.() -> Unit): CypherNode {
        val node = CypherNode(*labels)
        node.init()
        nodes.add(node)
        return node
    }

    fun cypherRelationship(from: CypherNode, label: String, to: CypherNode, bidirectional: Boolean, init: CypherRelationship.() -> Unit = {}): CypherRelationship {
        val relationship = CypherRelationship(from, label, to, bidirectional)
        relationship.init()
        relationships.add(relationship)
        return relationship
    }

    fun cypherRelationship(from: CypherNode, label: String, to: CypherNode, init: CypherRelationship.() -> Unit = {}): CypherRelationship {
        return cypherRelationship(from, label, to, false, init)
    }

    override fun toString(): String {

        val nodeString = nodes.joinToString("\n\t", "\n\t")
        val relationshipString = relationships.joinToString("\n\t", "\n\t")

        return """
            |Nodes: $nodeString
            |
            |Relationships: $relationshipString
        """.trimMargin("|")
    }

    fun fetchValuesFromDatabase(session: Session) {
        nodes.forEach { node ->
            node.properties.forEach { property ->
                populateValues(session, node, property)
            }
        }
    }

    private fun <T: Any> populateValues(session: Session, node: CypherNode, property: CypherProperty<T>) {
        val labels = node.labels.joinToString(":")
        val res = session.run("MATCH (n:$labels) where n.${property.name} is not NULL return distinct n.${property.name} as values")
        res.stream().map {
            it["values"]
        }.map {
            unwrap(it, property.type)
        }.forEach {
            property.values.add(it)
        }
    }

    private fun <T: Any> unwrap(value: Value, desiredType: KClass<T>): T {
        return when (desiredType) {
            String::class -> value.asString() as T
            Int::class, Long::class -> value.asLong() as T
            Float::class, Double::class -> value.asDouble() as T
            Boolean::class -> value.asBoolean() as T
            else -> value.asString() as T
        }
    }
}

class CypherNode(vararg val labels: String) {
    val properties = mutableSetOf<CypherProperty<*>>()

    fun toString(short: Boolean): String {
        val joinedLabels = if (labels.isEmpty()) "" else labels.joinToString(":", ":")
        return if (short) {
            "($joinedLabels)"
        } else {
            val props = properties.joinToString(", ") { "${it.name}: ${it.type.simpleName}" }
            "($joinedLabels {$props})"
        }
    }

    override fun toString(): String {
        return toString(false)
    }

    fun <T : Any> property(name: String, klass: KClass<T>, vararg values: T) {
        properties.add(CypherProperty(name, klass, values.toMutableSet()))
    }
}

class CypherProperty<T : Any>(
    val name: String,
    val type: KClass<T>,
    val values: MutableSet<T> = mutableSetOf<T>()
)

class CypherRelationship(
    val from: CypherNode,
    val label: String,
    val to: CypherNode,
    val bidirectional: Boolean
) {
    override fun toString(): String {
        val direction = if (bidirectional) "" else ">"
        val middlePart = if (label.isNotEmpty()) "[:$label]" else ""
        return "${from.toString(true)}-$middlePart-$direction${to.toString(true)}"
    }
}
