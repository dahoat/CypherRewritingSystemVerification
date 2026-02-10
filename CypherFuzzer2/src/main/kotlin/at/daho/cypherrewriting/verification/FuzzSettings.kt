package at.daho.cypherrewriting.verification

import kotlin.random.Random

data class PatternSettings(
    val patternsPerQuery: IntRange = 1..3,
    val length: IntRange = 1..4,
    val variableProbability: Double = 0.2
)

data class NodeSettings(
    val labelProbability: Double = 0.8,
    val defectLabelProbability: Double = 0.1,
    val labelsPerNode: IntRange = 1..2,
    val propertiesPerNode: IntRange = 0..2,
    val defectPropertyProbability: Double = 0.1,
    val defectPropertyTypeProbability: Double = 0.1,
    val variableProbability: Double = 0.9
)

data class RelationshipSettings(
    val labelProbability: Double = 0.7,
    val defectTypeProbability: Double = 0.1,
    val defectConnectionProbability: Double = 0.1,
    val defectDirectionProbability: Double = 0.1,
    val propertiesPerRelationship: IntRange = 0..1,
    val defectPropertyProbability: Double = 0.1,
    val bidirectionalProbability: Double = 0.1,
    val defectLabelProbability: Double = 0.1,
    val variableLengthRange: IntRange = 1..3,
    val variableProbability: Double = 0.6
)

data class OrderBySettings(
    val probability: Double = 0.2,
    val length: IntRange = 1..3,
    val ascProbability: Double = 0.33,
    val descProbability: Double = 0.33
) {
    init {
        require(ascProbability + descProbability <= 1.0) {
            "Sum of ascProbability ($ascProbability) and descProbability ($descProbability) must be at most 1.0"
        }
    }
}

data class ReturnSettings(
    val whereProbability: Double = 0.5,
    val limitProbability: Double = 0.3,
    val skipProbability: Double = 0.1,
    val distinctProbability: Double = 0.1,
    val limitRange: LongRange = 1L..100L,
    val skipRange: IntRange = 0..50,
    val length: IntRange = 1..5,
    val asteriskProbability: Double = 0.01,
    val orderBy: OrderBySettings = OrderBySettings(),
    val propertyAccessProbability: Double = 0.33,
)

data class FuzzSettings(
    val pattern: PatternSettings = PatternSettings(),
    val node: NodeSettings = NodeSettings(),
    val relationship: RelationshipSettings = RelationshipSettings(),
    val returnSettings: ReturnSettings = ReturnSettings(),
    val where: WhereSettings = WhereSettings(),
    val random: Random = Random(123),
    val useStoredValuesProbability: Double = 0.8
)

data class WhereSettings(
    val probability: Double = 0.1,
    val elementsRange: IntRange = 1..3,
    val successfulCheckProbability: Double = 0.95,
)

class WhereSettingsBuilder {
    var probability: Double = 0.1
    var elementsRange: IntRange = 1..3
    var successfulCheckProbability: Double = 0.95

    fun build(): WhereSettings = WhereSettings(
        probability = probability,
        elementsRange = elementsRange,
        successfulCheckProbability = successfulCheckProbability
    )
}

class PatternSettingsBuilder {
    var patternsPerQuery: IntRange = 1..3
    var length: IntRange = 1..4
    var variableProbability: Double = 0.2

    fun build(): PatternSettings = PatternSettings(
        patternsPerQuery = patternsPerQuery,
        length = length,
        variableProbability = variableProbability
    )
}

class NodeSettingsBuilder {
    var labelProbability: Double = 0.8
    var defectLabelProbability: Double = 0.1
    var labelsPerNode: IntRange = 1..2
    var propertiesPerNode: IntRange = 0..2
    var defectPropertyProbability: Double = 0.1
    var defectPropertyTypeProbability: Double = 0.1
    var variableProbability: Double = 0.9

    fun build(): NodeSettings = NodeSettings(
        labelProbability = labelProbability,
        defectLabelProbability = defectLabelProbability,
        labelsPerNode = labelsPerNode,
        propertiesPerNode = propertiesPerNode,
        defectPropertyProbability = defectPropertyProbability,
        defectPropertyTypeProbability = defectPropertyTypeProbability,
        variableProbability = variableProbability
    )
}

class RelationshipSettingsBuilder {
    var labelProbability: Double = 0.7
    var defectTypeProbability: Double = 0.1
    var defectConnectionProbability: Double = 0.1
    var defectDirectionProbability: Double = 0.1
    var propertiesPerRelationship: IntRange = 0..1
    var defectPropertyProbability: Double = 0.1
    var bidirectionalProbability: Double = 0.1
    var defectLabelProbability: Double = 0.1
    var variableLengthRange: IntRange = 1..3
    var variableProbability: Double = 0.6

    fun build(): RelationshipSettings = RelationshipSettings(
        labelProbability = labelProbability,
        defectTypeProbability = defectTypeProbability,
        defectConnectionProbability = defectConnectionProbability,
        defectDirectionProbability = defectDirectionProbability,
        propertiesPerRelationship = propertiesPerRelationship,
        defectPropertyProbability = defectPropertyProbability,
        bidirectionalProbability = bidirectionalProbability,
        defectLabelProbability = defectLabelProbability,
        variableLengthRange = variableLengthRange,
        variableProbability = variableProbability
    )
}

class OrderBySettingsBuilder {
    var probability: Double = 0.2
    var length: IntRange = 1..3
    var ascProbability: Double = 0.25
    var descProbability: Double = 0.25

    fun build(): OrderBySettings = OrderBySettings(
        probability = probability,
        length = length,
        ascProbability = ascProbability,
        descProbability = descProbability
    )
}

class ReturnSettingsBuilder {
    var limitProbability: Double = 0.3
    var skipProbability: Double = 0.1
    var distinctProbability: Double = 0.1
    var limitRange: LongRange = 1L..100L
    var skipRange: IntRange = 0..50
    var length: IntRange = 1..5
    var asteriskProbability: Double = 0.01
    private var orderByBuilder = OrderBySettingsBuilder()
    var propertyAccessProbability: Double = 0.33

    fun orderBy(init: OrderBySettingsBuilder.() -> Unit) {
        orderByBuilder.init()
    }

    fun build(): ReturnSettings = ReturnSettings(
        limitProbability = limitProbability,
        skipProbability = skipProbability,
        distinctProbability = distinctProbability,
        limitRange = limitRange,
        skipRange = skipRange,
        length = length,
        asteriskProbability = asteriskProbability,
        orderBy = orderByBuilder.build(),
        propertyAccessProbability = propertyAccessProbability
    )
}

class FuzzSettingsBuilder {
    private var patternBuilder = PatternSettingsBuilder()
    private var nodeBuilder = NodeSettingsBuilder()
    private var relationshipBuilder = RelationshipSettingsBuilder()
    private var returnBuilder = ReturnSettingsBuilder()
    private var whereBuilder = WhereSettingsBuilder()
    var seed: Long = 123
    var useStoredValuesProbability: Double = 0.8

    fun pattern(init: PatternSettingsBuilder.() -> Unit) {
        patternBuilder.init()
    }

    fun node(init: NodeSettingsBuilder.() -> Unit) {
        nodeBuilder.init()
    }

    fun relationship(init: RelationshipSettingsBuilder.() -> Unit) {
        relationshipBuilder.init()
    }

    fun returnSettings(init: ReturnSettingsBuilder.() -> Unit) {
        returnBuilder.init()
    }

    fun where(init: WhereSettingsBuilder.() -> Unit) {
        whereBuilder.init()
    }

    fun build(): FuzzSettings = FuzzSettings(
        pattern = patternBuilder.build(),
        node = nodeBuilder.build(),
        relationship = relationshipBuilder.build(),
        returnSettings = returnBuilder.build(),
        where = whereBuilder.build(),
        random = Random(seed),
        useStoredValuesProbability = useStoredValuesProbability
    )
}

fun fuzzSettings(init: FuzzSettingsBuilder.() -> Unit): FuzzSettings {
    val builder = FuzzSettingsBuilder()
    builder.init()
    return builder.build()
}
