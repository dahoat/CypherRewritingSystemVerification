package at.daho.cypherrewriting.verification

import at.jku.faw.symspace.cypherrewriter.core.cypher.AstInternalNode
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstLeafNoValue
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstLeafValue
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstNode
import at.jku.faw.symspace.cypherrewriter.core.cypher.AstType
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparser
import at.jku.faw.symspace.cypherrewriter.core.cypher.unparser.CypherRewritingUnparserImpl
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextLong
import kotlin.reflect.KClass
import kotlin.repeat

class FuzzGenerator(
    private val schema: CypherSchema,
    private val settings: FuzzSettings,
): Iterable<FuzzItem> {

    val unparser: CypherRewritingUnparser = CypherRewritingUnparserImpl()

    override fun iterator() = object : Iterator<FuzzItem> {
        override fun hasNext() = true

        override fun next(): FuzzItem {
            val fuzzQuery = FuzzQuery(schema, settings)
            val (ast, metrics) = fuzzQuery.generateWithMetrics()
            val query = unparser.render(ast)

            val mutated = fuzzQuery.mutateIndirectWhereValues()
            val variantQuery = if (mutated) unparser.render(ast) else null

            return FuzzItem(query, variantQuery, metrics)
        }
    }

}

class FuzzQuery(
    private val schema: CypherSchema,
    private val settings: FuzzSettings,
) {
    private var variableCount: Int = 0
    private val variableStore = VariableStore()
    private val filteredVariables = mutableSetOf<String>()
    private val returnedVariables = mutableSetOf<String>()
    private val whereElementInfos = mutableListOf<WhereElementInfo>()

    private val allowedNodes: Set<CypherNode> by lazy {
        val labels = settings.node.allowedLabels
        if (labels == null) {
            schema.nodes
        } else {
            schema.nodes.filter { node -> node.labels.any { it in labels } }.toSet()
        }
    }

    private data class WhereElementInfo(
        val varName: String,
        val structuralGroup: AstInternalNode,
        val operator: String,
        val isNullCheck: Boolean
    ) {
        fun getComparisonOperator(): AstLeafValue {
            val node = structuralGroup.elements.getOrNull(1)
            check(node is AstLeafValue && node.type == AstType.COMPARISON) {
                "Expected AstLeafValue(COMPARISON) at index 1 of STRUCTURAL_GROUP, but got: $node"
            }
            return node
        }

        fun setComparisonOperator(value: AstLeafValue) {
            check(value.type == AstType.COMPARISON) {
                "Expected AstLeafValue(COMPARISON), but got type: ${value.type}"
            }
            structuralGroup.elements[1] = value
        }
    }

    private companion object {
        const val OP_EQ = "="
        const val OP_NEQ = "<>"
        const val OP_LT = "<"
        const val OP_GT = ">"
        const val OP_LTE = "<="
        const val OP_GTE = ">="
        const val OP_STARTS_WITH = "STARTS WITH"
        const val OP_ENDS_WITH = "ENDS WITH"
        const val OP_CONTAINS = "CONTAINS"
        const val OP_IS_NULL = "IS NULL"
        const val OP_IS_NOT_NULL = "IS NOT NULL"

        const val VAR_PREFIX = "var"
        const val RANDOM_VAR_PREFIX = "randomVar"
        const val RANDOM_LABEL_PREFIX = "someRandomLabel"
    }

    fun generate(): AstInternalNode {
        val query = AstInternalNode(AstType.QUERY)
        query.elements.add(generateMatch())
        query.elements.add(generateReturn())
        return query
    }

    fun generateWithMetrics(): Pair<AstInternalNode, FuzzMetrics> {
        val ast = generate()
        val labeledVars = variableStore.allVariables()
            .associateWith { variableStore.getLabels(it) }
            .filterValues { it.isNotEmpty() }
        return ast to FuzzMetrics(labeledVars, filteredVariables.toSet(), returnedVariables.toSet())
    }

    fun mutateIndirectWhereValues(): Boolean {
        val indirectVars = filteredVariables - returnedVariables
        if (indirectVars.isEmpty()) return false

        var mutated = false
        for (info in whereElementInfos) {
            if (info.varName in indirectVars) {
                if (info.isNullCheck) {
                    val currentOp = info.getComparisonOperator().value.toString()
                    val flipped = if (currentOp == OP_IS_NULL) {
                        OP_IS_NOT_NULL
                    } else {
                        OP_IS_NULL
                    }
                    info.setComparisonOperator(AstLeafValue(AstType.COMPARISON, flipped))
                } else {
                    val flippedOp = flipOperator(info.operator)
                    info.setComparisonOperator(AstLeafValue(AstType.COMPARISON, flippedOp))
                }
                mutated = true
            }
        }
        return mutated
    }

    private fun flipOperator(operator: String): String = when (operator) {
        OP_EQ -> OP_NEQ
        OP_NEQ -> OP_EQ
        OP_LT -> OP_GTE
        OP_GTE -> OP_LT
        OP_GT -> OP_LTE
        OP_LTE -> OP_GT
        OP_STARTS_WITH -> OP_NEQ
        OP_ENDS_WITH -> OP_NEQ
        OP_CONTAINS -> OP_NEQ
        else -> OP_EQ
    }

    private fun generateMatch(): AstNode {
        val match = AstInternalNode(AstType.MATCH)

        repeat(selectCount(settings.pattern.patternsPerQuery)) {
            match.elements.add(generatePattern())
        }

        if (flipCoin(settings.where.probability)) {
            match.elements.add(generateWhere())
        }

        return match
    }

    private fun generateWhere(): AstNode {
        val where = AstInternalNode(AstType.WHERE)
        val elements = mutableListOf<AstInternalNode>()

        repeat(selectCount(settings.where.length)) {
            generateWhereElement().let { elements.add(it) }
        }
        where.elements.add(combineWhereElements(elements))

        return where
    }

    private fun combineWhereElements(elements: List<AstInternalNode>, outerOperator: AstType? = null): AstInternalNode {
        if (elements.size == 1) {
            return elements[0]
        }

        val splitLocation = settings.random.nextInt(1, elements.size)
        val leftSublist = elements.subList(0, splitLocation)
        val rightSublist = elements.subList(splitLocation, elements.size)
        val booleanOperator = listOf(AstType.AND, AstType.OR, AstType.XOR).random(settings.random)

        val res = AstInternalNode(booleanOperator)
        res.elements.add(combineWhereElements(leftSublist, booleanOperator))
        res.elements.add(combineWhereElements(rightSublist, booleanOperator))

        if (outerOperator != null && hasLowerPrecedence(booleanOperator, outerOperator)) {
            val group = AstInternalNode(AstType.GROUP)
            group.elements.add(res)
            return group
        }
        return res
    }

    private fun hasLowerPrecedence(currentOperator: AstType, outerOperator: AstType): Boolean {
        val precedence = mapOf(AstType.OR to 0, AstType.XOR to 1, AstType.AND to 2)
        return (precedence[currentOperator] ?: 0) < (precedence[outerOperator] ?: 0)
    }

    private fun generateWhereElement(): AstInternalNode {
        val varName = if (variableStore.isNotEmpty()) {
            variableStore.random(settings.random)
        } else {
            RANDOM_VAR_PREFIX + settings.random.nextInt()
        }
        filteredVariables.add(varName)
        val variable = AstLeafValue(AstType.VARIABLE, varName)
        val properties = resolvePropertiesForVariable(varName)

        val selectedProperty = if (properties.isNotEmpty()) {
            properties.random(settings.random)
        } else {
            CypherProperty(randomString(), randomType())
        }

        val group = AstInternalNode(AstType.STRUCTURAL_GROUP)
        group.elements.add(buildPropertyDotAccess(variable, selectedProperty.name))

        if (flipCoin(settings.where.nullCheckProbability)) {
            val nullOp = if (settings.random.nextBoolean()) OP_IS_NULL else OP_IS_NOT_NULL
            group.elements.add(AstLeafValue(AstType.COMPARISON, nullOp))
            whereElementInfos.add(WhereElementInfo(varName, group, nullOp, isNullCheck = true))
        } else {
            val operator = selectComparisonOperator(selectedProperty.type)
            val successful = flipCoin(settings.where.successfulCheckProbability)
            group.elements.add(AstLeafValue(AstType.COMPARISON, operator))
            group.elements.add(generateWhereValue(selectedProperty, operator, forceSuccessful = successful))
            whereElementInfos.add(WhereElementInfo(varName, group, operator, isNullCheck = false))
        }

        return group
    }

    private fun resolvePropertiesForVariable(varName: String): List<CypherProperty<*>> {
        val labels = variableStore.getLabels(varName)
        return schema.nodes
            .filter { it.labels.intersect(labels.toSet()).isNotEmpty() }
            .flatMap { it.properties }
    }

    private fun selectComparisonOperator(type: KClass<*>): String {
        val operators = when (type) {
            String::class -> listOf(OP_EQ, OP_NEQ, OP_STARTS_WITH, OP_ENDS_WITH, OP_CONTAINS)
            Int::class, Long::class, Double::class, Float::class -> listOf(OP_EQ, OP_NEQ, OP_LT, OP_GT, OP_LTE, OP_GTE)
            Boolean::class -> listOf(OP_EQ, OP_NEQ)
            else -> listOf(OP_EQ, OP_NEQ)
        }
        return operators.random(settings.random)
    }

    private fun generateWhereValue(property: CypherProperty<out Any>, operator: String, forceSuccessful: Boolean? = null): AstNode {
        val successful = forceSuccessful ?: flipCoin(settings.where.successfulCheckProbability)
        val type = property.type
        val storedValue = if (property.values.isNotEmpty()) property.values.random(settings.random) else null

        return when (type) {
            String::class -> generateStringWhereValue(storedValue as String?, operator, successful)
            Int::class, Long::class -> generateNumericWhereValue(storedValue as Long?, operator, successful)
            Double::class, Float::class -> generateDoubleWhereValue(storedValue as Double?, operator, successful)
            Boolean::class -> generateBooleanWhereValue(storedValue as Boolean?, operator, successful)
            else -> generateStringWhereValue(storedValue?.toString(), operator, successful)
        }
    }

    private fun generateStringWhereValue(storedValue: String?, operator: String, successful: Boolean): AstLeafValue {
        val value = storedValue ?: randomString()

        val resultValue = when (operator) {
            OP_EQ -> if (successful) value else randomString()
            OP_NEQ -> if (successful) randomString() else value
            OP_STARTS_WITH, OP_ENDS_WITH, OP_CONTAINS -> alterStringForOperator(value, operator, successful)
            else -> value
        }

        return AstLeafValue(AstType.STRING, "\"${escapeString(resultValue)}\"")
    }

    private fun escapeString(input: String?): String? {
        if (input == null) {
            return null
        }
        return input.replace("\\", "\\\\").replace("\"", "\\\"")
    }

    private fun alterStringForOperator(value: String, operator: String, successful: Boolean): String {
        if (value.isEmpty()) return randomString()

        return when (operator) {
            OP_STARTS_WITH -> if (successful) {
                value.substring(0, settings.random.nextInt(1, value.length + 1))
            } else {
                randomString() + value
            }
            OP_ENDS_WITH -> if (successful) {
                value.substring(settings.random.nextInt(0, value.length))
            } else {
                value + randomString()
            }
            OP_CONTAINS -> if (successful) {
                val start = settings.random.nextInt(0, value.length)
                val end = settings.random.nextInt(start + 1, value.length + 1)
                value.substring(start, end)
            } else {
                randomString()
            }
            else -> value
        }
    }

    private fun generateNumericWhereValue(storedValue: Long?, operator: String, successful: Boolean): AstLeafValue {
        val value = storedValue ?: settings.random.nextLong(-1000, 1000)

        val resultValue = when (operator) {
            OP_EQ -> if (successful) value else value + settings.random.nextLong(1, 100)
            OP_NEQ -> if (successful) value + settings.random.nextLong(1, 100) else value
            OP_LT -> if (successful) value + settings.random.nextLong(1, 100) else value - settings.random.nextLong(1, 100)
            OP_LTE -> if (successful) value + settings.random.nextLong(0, 100) else value - settings.random.nextLong(1, 100)
            OP_GT -> if (successful) value - settings.random.nextLong(1, 100) else value + settings.random.nextLong(1, 100)
            OP_GTE -> if (successful) value - settings.random.nextLong(0, 100) else value + settings.random.nextLong(1, 100)
            else -> value
        }

        return AstLeafValue(AstType.INTEGER, resultValue)
    }

    private fun generateDoubleWhereValue(storedValue: Double?, operator: String, successful: Boolean): AstLeafValue {
        val value = storedValue ?: settings.random.nextDouble(-1000.0, 1000.0)
        val offset = settings.random.nextDouble(0.1, 100.0)

        val resultValue = when (operator) {
            OP_EQ -> if (successful) value else value + offset
            OP_NEQ -> if (successful) value + offset else value
            OP_LT -> if (successful) value + offset else value - offset
            OP_LTE -> if (successful) value + offset else value - offset
            OP_GT -> if (successful) value - offset else value + offset
            OP_GTE -> if (successful) value - offset else value + offset
            else -> value
        }

        return AstLeafValue(AstType.DOUBLE, resultValue)
    }

    private fun generateBooleanWhereValue(storedValue: Boolean?, operator: String, successful: Boolean): AstLeafValue {
        val value = storedValue ?: settings.random.nextBoolean()

        val resultValue = when (operator) {
            OP_EQ -> if (successful) value else !value
            OP_NEQ -> if (successful) !value else value
            else -> value
        }

        return AstLeafValue(AstType.BOOLEAN, resultValue)
    }

    private fun generateReturn(): AstNode {
        val returnNode = AstInternalNode(AstType.RETURN)

        handleDistinct(returnNode)
        handleReturnItems(returnNode)
        handleOrderBy(returnNode)
        handleSkip(returnNode)
        handleLimit(returnNode)

        return returnNode
    }

    private fun handleLimit(returnNode: AstInternalNode) {
        if (settings.returnSettings.generateLimit && flipCoin(settings.returnSettings.limitProbability)) {
            val limit = AstInternalNode(AstType.LIMIT).apply {
                elements.add(
                    AstLeafValue(
                        AstType.INTEGER,
                        settings.random.nextLong(settings.returnSettings.limitRange)
                    )
                )
            }
            returnNode.elements.add(limit)
        }
    }

    private fun handleSkip(returnNode: AstInternalNode) {
        if (settings.returnSettings.generateSkip && flipCoin(settings.returnSettings.skipProbability)) {
            val skip = AstInternalNode(AstType.SKIP).apply {
                elements.add(
                    AstLeafValue(
                        AstType.INTEGER,
                        settings.random.nextInt(settings.returnSettings.skipRange).toLong()
                    )
                )
            }
            returnNode.elements.add(skip)
        }
    }

    private fun handleOrderBy(returnNode: AstInternalNode) {
        if (flipCoin(settings.returnSettings.orderBy.probability) && variableStore.isNotEmpty()) {
            returnNode.elements.add(generateOrderBy())
        }
    }

    private fun handleReturnItems(returnNode: AstInternalNode) {
        if (variableStore.isEmpty() || flipCoin(settings.returnSettings.asteriskProbability)) {
            returnNode.elements.add(AstLeafNoValue(AstType.ASTERISK))
            returnedVariables.addAll(variableStore.allVariables())
        } else {
            repeat(selectCount(settings.returnSettings.length)) {
                returnNode.elements.add(selectElementForReturn())
            }
        }
    }

    private fun handleDistinct(returnNode: AstInternalNode) {
        if (flipCoin(settings.returnSettings.distinctProbability)) {
            returnNode.elements.add(AstLeafNoValue(AstType.DISTINCT))
        }
    }

    private fun generateOrderBy(): AstInternalNode {
        val orderBy = AstInternalNode(AstType.ORDER_BY)
        val orderBySettings = settings.returnSettings.orderBy

        repeat(selectCount(orderBySettings.length)) {
            val sortItem = AstInternalNode(AstType.SORT_ITEM)
            sortItem.elements.add(selectElementForReturn())

            val randomSelection = settings.random.nextDouble()
            when {
                randomSelection < orderBySettings.ascProbability -> sortItem.elements.add(AstLeafNoValue(AstType.ASC))
                randomSelection < orderBySettings.ascProbability + orderBySettings.descProbability -> sortItem.elements.add(AstLeafNoValue(AstType.DESC))
                // else: no explicit direction (default)
            }
            orderBy.elements.add(sortItem)
        }
        return orderBy
    }

    private fun selectElementForReturn(): AstNode {
        val varName = variableStore.random(settings.random)
        returnedVariables.add(varName)
        val variable = AstLeafValue(AstType.VARIABLE, varName)

        val baseElement = if (flipCoin(settings.returnSettings.propertyAccessProbability)) {
            val labels = variableStore.getLabels(varName)
            val properties = schema.nodes.filter { it.labels.intersect(labels.toSet()).isNotEmpty() }.flatMap { it.properties }
            if (properties.isNotEmpty()) {
                buildPropertyDotAccess(variable, properties.random(settings.random).name)
            } else {
                variable
            }
        } else {
            variable
        }

        if (flipCoin(settings.returnSettings.aggregationProbability)) {
            return generateAggregationFunction(baseElement)
        }
        return baseElement
    }

    private fun generateAggregationFunction(innerElement: AstNode): AstNode {
        val functionInvocation = AstInternalNode(AstType.FUNCTION_INVOCATION)
        val funcName = settings.returnSettings.aggregationFunctions.random(settings.random)
        functionInvocation.elements.add(AstLeafValue(AstType.FUNCTION_NAME, funcName))
        val argument = AstInternalNode(AstType.ARGUMENT)
        argument.elements.addAll(if (innerElement is AstInternalNode) innerElement.elements else listOf(innerElement))
        functionInvocation.elements.add(argument)
        return functionInvocation
    }

    private fun buildPropertyDotAccess(variable: AstLeafValue, propName: String): AstInternalNode {
        val propertyDotAccess = AstInternalNode(AstType.PROPERTY_DOT_ACCESS)
        propertyDotAccess.elements.add(variable)
        propertyDotAccess.elements.add(AstLeafValue(AstType.PROPERTY_KEY_NAME, propName))
        return propertyDotAccess
    }

    private fun generatePattern(): AstInternalNode {
        val patternContext = PatternContext()
        val pattern = AstInternalNode(AstType.PATTERN)

        val numElements = selectCount(settings.pattern.length)
        repeat(numElements) { index ->
            if (index == 0) {
                pattern.elements.add(generateNode(patternContext))
            } else {
                patternContext.prepareForRelationship()
                val node = generateNode(patternContext)
                val relationship = generateRelationship(patternContext)

                pattern.elements.add(relationship)
                pattern.elements.add(node)
            }
        }

        return pattern
    }

    private fun generateNode(patternContext: PatternContext): AstInternalNode {
        val node = AstInternalNode(AstType.NODE)
        var variableNode: AstLeafValue? = null
        var labelNodes: List<AstLeafValue>? = null
        patternContext.currentCypherNode = allowedNodes.random(settings.random)

        if (flipCoin(settings.node.variableProbability)) {
            variableNode = nextVariable()
            node.elements.add(variableNode)
        }

        repeat(selectCount(settings.node.labelsPerNode)) {
            labelNodes = generateNodeLabel(patternContext)
            node.elements.addAll(labelNodes)
        }

        variableStore.addNodeVariable(variableNode, labelNodes)

        val propertyNodes = mutableListOf<AstInternalNode>()
        repeat(selectCount(settings.node.propertiesPerNode)) {
            propertyNodes.add(generatePropertyNode(patternContext))
        }
        if (propertyNodes.isNotEmpty()) {
            val properties = AstInternalNode(AstType.PROPERTIES)
            properties.elements.addAll(propertyNodes)
            node.elements.add(properties)
        }

        return node
    }

    private fun generateRelationship(patternContext: PatternContext): AstInternalNode {

        val fromLastNode = schema.relationships.filter { it.from == patternContext.previousCypherNode }.filter { it.to == patternContext.currentCypherNode }
        val toLastNode = schema.relationships.filter { it.to == patternContext.previousCypherNode }.filter { it.from == patternContext.currentCypherNode }

        val direction: AstType
        val label: String?
        if (fromLastNode.isNotEmpty() || toLastNode.isNotEmpty()) {
            val relationshipSchema = (fromLastNode + toLastNode).random(settings.random)

            direction = if (relationshipSchema.bidirectional && flipCoin(settings.relationship.bidirectionalProbability)) {
                AstType.RELATION_BOTH
            } else if (relationshipSchema in fromLastNode) {
                AstType.RELATION_RIGHT
            } else if (relationshipSchema in toLastNode) {
                AstType.RELATION_LEFT
            } else {
                error("Could not determine relationship direction to use.")
            }
            label = relationshipSchema.label
        } else {
            direction = setOf(AstType.RELATION_BOTH, AstType.RELATION_LEFT, AstType.RELATION_RIGHT).random(settings.random)
            label = if(flipCoin(settings.relationship.labelProbability)) {
                randomLabel()
            } else {
                null
            }
        }

        val relationship = AstInternalNode(direction)

        var relationshipVariable: AstLeafValue? = null
        if (flipCoin(settings.relationship.variableProbability)) {
            relationshipVariable = nextVariable()
            relationship.elements.add(relationshipVariable)
        }

        var labelNode: AstLeafValue? = null
        if (label != null) {
            labelNode = AstLeafValue(AstType.RELATION_LABEL, label)
            relationship.elements.add(labelNode)
        }

        variableStore.addRelationshipVariable(relationshipVariable, labelNode)

        return relationship
    }

    private fun nextVariable(): AstLeafValue {
        val variable = AstLeafValue(AstType.VARIABLE, VAR_PREFIX + variableCount++)
        return variable
    }

    private fun generateNodeLabel(patternContext: PatternContext): List<AstLeafValue> {
        val labels = if (flipCoin(settings.node.defectLabelProbability)) {
            arrayOf(randomLabel())
        } else {
            patternContext.currentCypherNode!!.labels
        }

        return labels.map { AstLeafValue(AstType.NODE_LABEL, it) }
    }

    private fun flipCoin(probability: Double): Boolean {
        return settings.random.nextDouble() < probability
    }

    private fun selectCount(range: IntRange): Int {
        return settings.random.nextInt(range)
    }

    private fun randomLabel(): String {
        return RANDOM_LABEL_PREFIX + settings.random.nextInt(100)
    }

    private fun generatePropertyNode(patternContext: PatternContext): AstInternalNode {

        val currentNodeSchema = patternContext.currentCypherNode
        val selectedProperty = currentNodeSchema?.properties?.random(settings.random) ?: CypherProperty(randomString(), randomType())

        val structuralGroup = AstInternalNode(AstType.STRUCTURAL_GROUP)
        structuralGroup.elements.add(generatePropertyValueNode(selectedProperty.type, selectedProperty))
        val propertyNode = AstInternalNode(AstType.PROPERTY)
        propertyNode.elements.add(AstLeafValue(AstType.PROPERTY_KEY_NAME, selectedProperty.name))
        propertyNode.elements.add(structuralGroup)
        return propertyNode
    }

    private fun randomType(): KClass<*> {
        return setOf(String::class, Boolean::class, Int::class, Long::class, Double::class).random(settings.random)
    }

    private fun generatePropertyValueNode(type: KClass<*>, cypherProperty: CypherProperty<out Any>): AstLeafValue {

        val value = if (cypherProperty.values.isNotEmpty()) {
            val rawValue = cypherProperty.values.random(settings.random)
            if (rawValue is String) {
                escapeString(rawValue)
            } else {
                rawValue
            }
        } else {
            null
        }

        return when (type) {
            String::class -> AstLeafValue(AstType.STRING, "\"$value\"" as String? ?: "\"${randomString()}\"")
            Int::class, Long::class -> AstLeafValue(AstType.INTEGER, value as Long? ?: settings.random.nextLong(-1000, 1000))
            Double::class, Float::class -> AstLeafValue(AstType.DOUBLE, value as Double? ?: settings.random.nextDouble(-1000.0, 1000.0))
            Boolean::class -> AstLeafValue(AstType.BOOLEAN, value as Boolean? ?: settings.random.nextBoolean())
            else -> AstLeafValue(AstType.STRING, value?.toString() ?: randomString())
        }
    }

    private fun randomString(): String {
        val words = listOf("alpha", "beta", "gamma", "delta", "test", "value")
        return words.random(settings.random) + settings.random.nextInt(1000)
    }
}

class VariableStore {
    private var variables = mutableSetOf<String>()
    private var nodeVariables = mutableMapOf<String, MutableList<String>>()
    private var relationshipVariables = mutableMapOf<String, MutableList<String>>()

    fun addNodeVariable(variableNode: AstLeafValue?, labelNodes: List<AstLeafValue>?) {
        if(variableNode != null) {
            val variable = variableNode.value.toString()
            variables.add(variable)
            nodeVariables.putIfAbsent(variable, mutableListOf())

            if (labelNodes != null) {
                val labels = labelNodes.map { it.value.toString() }.filter { it.isNotBlank() }
                nodeVariables[variable]!!.addAll(labels)
            }
        }
    }

    fun addRelationshipVariable(variableNode: AstLeafValue?, labelNode: AstLeafValue?) {
        if (variableNode != null) {
            val variable = variableNode.value.toString()
            variables.add(variable)
            relationshipVariables.putIfAbsent(variable, mutableListOf())

            if (labelNode != null) {
                val label = labelNode.value.toString()
                if (label.isNotBlank()) {
                    relationshipVariables[variable]!!.add(label)
                }
            }
        }
    }

    fun isNotEmpty(): Boolean {
        return variables.isNotEmpty()
    }

    fun isEmpty(): Boolean {
        return variables.isEmpty()
    }

    fun random(random: Random): String {
        return variables.random(random)
    }

    fun allVariables(): Set<String> = variables.toSet()

    fun getLabels(variable: String): Set<String> {
        if (variable in nodeVariables) {
            return nodeVariables[variable]!!.toSet()
        }
        if (variable in relationshipVariables) {
            return relationshipVariables[variable]!!.toSet()
        }
        return setOf()
    }
}

class PatternContext {
    var previousCypherNode: CypherNode? = null
    var currentCypherNode: CypherNode? = null

    fun prepareForRelationship() {
        previousCypherNode = currentCypherNode
        currentCypherNode = null
    }
}
