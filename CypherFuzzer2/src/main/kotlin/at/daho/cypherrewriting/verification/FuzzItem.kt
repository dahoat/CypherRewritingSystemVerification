package at.daho.cypherrewriting.verification

data class FuzzItem(
    val query: String,
    val mutatedQuery: String?,
    val metrics: FuzzMetrics
)
