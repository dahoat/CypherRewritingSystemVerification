package at.daho.cypherrewriting.verification

import kotlin.random.Random

@DslMarker
annotation class FuzzSettingsDsl

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
    val variableProbability: Double = 0.9,
    val allowedLabels: Set<String>? = null
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
    val generateLimit: Boolean = true,
    val limitProbability: Double = 0.3,
    val generateSkip: Boolean = true,
    val skipProbability: Double = 0.1,
    val distinctProbability: Double = 0.1,
    val limitRange: LongRange = 1L..100L,
    val skipRange: IntRange = 0..50,
    val length: IntRange = 1..5,
    val asteriskProbability: Double = 0.01,
    val orderBy: OrderBySettings = OrderBySettings(),
    val propertyAccessProbability: Double = 0.33,
    val aggregationProbability: Double = 0.0,
    val aggregationFunctions: List<String> = listOf("count", "sum", "avg", "min", "max", "collect"),
)

data class FuzzSettings(
    val pattern: PatternSettings = PatternSettings(),
    val node: NodeSettings = NodeSettings(),
    val relationship: RelationshipSettings = RelationshipSettings(),
    val returnSettings: ReturnSettings = ReturnSettings(),
    val where: WhereSettings = WhereSettings(),
    val random: Random = Random.Default,
    val useStoredValuesProbability: Double = 0.8
)

data class WhereSettings(
    val probability: Double = 0.1,
    val length: IntRange = 1..3,
    val successfulCheckProbability: Double = 0.95,
    val nullCheckProbability: Double = 0.1,
)

@FuzzSettingsDsl
class WhereSettingsBuilder {
    var probability: Double = 0.1
    var length: IntRange = 1..3
    var successfulCheckProbability: Double = 0.95
    var nullCheckProbability: Double = 0.1

    fun build(): WhereSettings = WhereSettings(
        probability = probability,
        length = length,
        successfulCheckProbability = successfulCheckProbability,
        nullCheckProbability = nullCheckProbability
    )
}

@FuzzSettingsDsl
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

@FuzzSettingsDsl
class NodeSettingsBuilder {
    var labelProbability: Double = 0.8
    var defectLabelProbability: Double = 0.1
    var labelsPerNode: IntRange = 1..2
    var propertiesPerNode: IntRange = 0..2
    var defectPropertyProbability: Double = 0.1
    var defectPropertyTypeProbability: Double = 0.1
    var variableProbability: Double = 0.9
    var allowedLabels: Set<String>? = null

    fun build(): NodeSettings = NodeSettings(
        labelProbability = labelProbability,
        defectLabelProbability = defectLabelProbability,
        labelsPerNode = labelsPerNode,
        propertiesPerNode = propertiesPerNode,
        defectPropertyProbability = defectPropertyProbability,
        defectPropertyTypeProbability = defectPropertyTypeProbability,
        variableProbability = variableProbability,
        allowedLabels = allowedLabels
    )
}

@FuzzSettingsDsl
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

@FuzzSettingsDsl
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

@FuzzSettingsDsl
class ReturnSettingsBuilder {
    var generateLimit: Boolean = true
    var limitProbability: Double = 0.3
    var generateSkip: Boolean = true
    var skipProbability: Double = 0.1
    var distinctProbability: Double = 0.1
    var limitRange: LongRange = 1L..100L
    var skipRange: IntRange = 0..50
    var length: IntRange = 1..5
    var asteriskProbability: Double = 0.01
    private var orderByBuilder = OrderBySettingsBuilder()
    var propertyAccessProbability: Double = 0.33
    var aggregationProbability: Double = 0.0
    var aggregationFunctions: List<String> = listOf("count", "sum", "avg", "min", "max", "collect")

    fun orderBy(init: OrderBySettingsBuilder.() -> Unit) {
        orderByBuilder.init()
    }

    fun build(): ReturnSettings = ReturnSettings(
        generateLimit = generateLimit,
        limitProbability = limitProbability,
        generateSkip = generateSkip,
        skipProbability = skipProbability,
        distinctProbability = distinctProbability,
        limitRange = limitRange,
        skipRange = skipRange,
        length = length,
        asteriskProbability = asteriskProbability,
        orderBy = orderByBuilder.build(),
        propertyAccessProbability = propertyAccessProbability,
        aggregationProbability = aggregationProbability,
        aggregationFunctions = aggregationFunctions
    )
}

@FuzzSettingsDsl
class FuzzSettingsBuilder {
    private var patternBuilder = PatternSettingsBuilder()
    private var nodeBuilder = NodeSettingsBuilder()
    private var relationshipBuilder = RelationshipSettingsBuilder()
    private var returnBuilder = ReturnSettingsBuilder()
    private var whereBuilder = WhereSettingsBuilder()
    var seed: Long? = null
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
        random = seed?.let { Random(it) } ?: Random.Default,
        useStoredValuesProbability = useStoredValuesProbability
    )
}

fun fuzzSettings(init: FuzzSettingsBuilder.() -> Unit): FuzzSettings {
    val builder = FuzzSettingsBuilder()
    builder.init()
    return builder.build()
}
