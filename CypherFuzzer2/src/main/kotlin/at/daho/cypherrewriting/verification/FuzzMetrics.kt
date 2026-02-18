package at.daho.cypherrewriting.verification

data class FuzzMetrics(
    val labeledVariables: Map<String, Set<String>>,
    val filteredVariables: Set<String>,
    val returnedVariables: Set<String>
) {
    fun variablesWithLabel(label: String): Set<String> =
        labeledVariables.filter { label in it.value }.keys
}
